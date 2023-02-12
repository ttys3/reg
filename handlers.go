package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/distribution/distribution/v3/manifest/ocischema"
	"github.com/labstack/echo/v4"
	ociv1 "github.com/opencontainers/image-spec/specs-go/v1"
	"html/template"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/genuinetools/reg/clair"
	"github.com/genuinetools/reg/registry"
	"github.com/sirupsen/logrus"
)

type registryController struct {
	reg          *registry.Registry
	cl           *clair.Clair
	interval     time.Duration
	l            sync.Mutex
	tmpl         *template.Template
	generateOnly bool
}

type v1Compatibility struct {
	ID      string    `json:"id"`
	Created time.Time `json:"created"`
}

// A Repository holds data after a vulnerability scan of a single repo
type Repository struct {
	Name                string                    `json:"name"`
	Tag                 string                    `json:"tag"`
	Created             *time.Time                `json:"created,omitempty"` // only "Image Manifest Version 2, Schema 1" has this field
	URI                 string                    `json:"uri"`
	ImageType           string                    `json:"image_type"`
	VulnerabilityReport clair.VulnerabilityReport `json:"vulnerability"`
}

// An AnalysisResult holds all vulnerabilities of a scan
type AnalysisResult struct {
	Repositories   []Repository `json:"repositories"`
	RegistryDomain string       `json:"registryDomain"`
	Name           string       `json:"name"`
	LastUpdated    string       `json:"lastUpdated"`
	HasVulns       bool         `json:"hasVulns"`
	UpdateInterval time.Duration
}

func (rc *registryController) repositories(ctx context.Context, staticDir string) error {
	rc.l.Lock()
	defer rc.l.Unlock()

	logrus.Infof("fetching catalog for %s...", rc.reg.Domain)

	result := AnalysisResult{
		RegistryDomain: rc.reg.Domain,
		LastUpdated:    time.Now().Local().Format(time.RFC1123),
		UpdateInterval: rc.interval,
	}

	repoList, err := rc.reg.Catalog(ctx, "")
	if err != nil {
		return fmt.Errorf("getting catalog for %s failed: %v", rc.reg.Domain, err)
	}

	var wg sync.WaitGroup
	for _, repo := range repoList {
		repoURI := fmt.Sprintf("%s/%s", rc.reg.Domain, repo)
		r := Repository{
			Name: repo,
			URI:  repoURI,
		}

		result.Repositories = append(result.Repositories, r)

		if !rc.generateOnly {
			// Continue early because we don't need to generate the tags pages.
			continue
		}

		// Generate the tags pages in a go routine.
		wg.Add(1)
		go func(repo string) {
			defer wg.Done()
			logrus.Infof("generating static tags page for repo %s", repo)

			// Parse and execute the tags templates.
			// If we are generating the tags files, disable vulnerability links in the
			// templates since they won't go anywhere without a server side component.
			b, err := rc.generateTagsTemplate(ctx, repo, false)
			if err != nil {
				logrus.Warnf("generating tags template for repo %q failed: %v", repo, err)
			}
			// Create the directory for the static tags files.
			tagsDir := filepath.Join(staticDir, "repo", repo, "tags")
			if err := os.MkdirAll(tagsDir, 0755); err != nil {
				logrus.Warn(err)
			}

			// Write the tags file.
			tagsFile := filepath.Join(tagsDir, "index.html")
			if err := ioutil.WriteFile(tagsFile, b, 0755); err != nil {
				logrus.Warnf("writing tags template for repo %s to %sfailed: %v", repo, tagsFile, err)
			}
		}(repo)
	}
	wg.Wait()

	// Parse & execute the template.
	logrus.Info("executing the template repositories")

	// Create the static directory.
	if err := os.MkdirAll(staticDir, 0755); err != nil {
		return err
	}

	// Creating the index file.
	path := filepath.Join(staticDir, "index.html")
	logrus.Debugf("creating/opening file %s", path)
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	// Execute the template on the index.html file.
	if err := rc.tmpl.ExecuteTemplate(f, "repositories", result); err != nil {
		f.Close()
		return fmt.Errorf("execute template repositories failed: %v", err)
	}

	return nil
}

func (rc *registryController) tagsHandler(c echo.Context) error {
	logrus.WithFields(logrus.Fields{
		"func":   "tags",
		"URL":    c.Request().URL,
		"method": c.Request().Method,
	}).Info("fetching tags")

	// Parse the query variables.
	repo, err := url.QueryUnescape(c.Param("repo"))
	if err != nil || repo == "" {
		return c.String(http.StatusNotFound, "Empty repo")
	}

	// Generate the tags template.
	b, err := rc.generateTagsTemplate(context.TODO(), repo, rc.cl != nil)
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"func":   "tags",
			"URL":    c.Request().URL,
			"method": c.Request().Method,
		}).Errorf("getting tags for %s failed: %v", repo, err)

		return c.String(http.StatusInternalServerError, fmt.Sprintf("Getting tags for %s failed", repo))
	}

	// Write the template.
	return c.HTML(http.StatusOK, string(b))
}

func (rc *registryController) generateTagsTemplate(ctx context.Context, repo string, hasVulns bool) ([]byte, error) {
	// Get the tags from the server.
	tags, err := rc.reg.Tags(ctx, repo)
	if err != nil {
		return nil, fmt.Errorf("getting tags for %s failed: %v", repo, err)
	}

	// Error out if there are no tags / images
	// (the above err != nil does not error out when nothing has been found)
	if len(tags) == 0 {
		return nil, fmt.Errorf("no tags found for repo: %s", repo)
	}

	result := AnalysisResult{
		RegistryDomain: rc.reg.Domain,
		LastUpdated:    time.Now().Local().Format(time.RFC1123),
		UpdateInterval: rc.interval,
		Name:           repo,
		HasVulns:       hasVulns, // if we have a clair client we can return vulns
	}

	for _, tag := range tags {
		// get the image creat time, for v2 or oci image,
		// maybe someday we can get it from `org.opencontainers.image.created` annotation
		// ref https://github.com/opencontainers/image-spec/blob/main/annotations.md#pre-defined-annotation-keys
		m1, err := rc.reg.ManifestV1(ctx, repo, tag)
		var createdDate *time.Time
		var imageType string
		if err != nil {
			// skip htp error
			logrus.Warnf("getting v1 manifest for %s:%s failed: %v, try v2 and oci", repo, tag, err)
			if errors.Is(err, registry.ErrResourceNotFound) {
				manifest, descriptor, err := rc.reg.Manifest(ctx, repo, tag)
				if err != nil {
					logrus.Errorf("getting v2 or oci manifest for %s:%s failed: %v", repo, tag, err)
				} else if descriptor.MediaType == ociv1.MediaTypeImageManifest {
					if ocimanifest, ok := manifest.(*ocischema.DeserializedManifest); ok && ocimanifest.Annotations != nil {
						if created, ok := ocimanifest.Annotations["org.opencontainers.image.created"]; ok {
							if t, err := time.Parse(time.RFC3339, created); err == nil {
								createdDate = &t
							}
						}
					}
					imageType = "OCI"
				} else {
					logrus.Warnf("can not get created time, unsupported manifest type %s for %s:%s",
						descriptor.MediaType, repo, tag)
					imageType = "Docker V2"
				}
			}
		} else {
			for _, h := range m1.History {
				var comp v1Compatibility

				if err := json.Unmarshal([]byte(h.V1Compatibility), &comp); err != nil {
					return nil, fmt.Errorf("unmarshal v1 manifest for %s:%s failed: %v", repo, tag, err)
				}
				createdDate = &comp.Created
				imageType = "Docker V1"
				break
			}
		}

		repoURI := fmt.Sprintf("%s/%s", rc.reg.Domain, repo)
		if tag != "latest" {
			repoURI += ":" + tag
		}
		rp := Repository{
			Name:      repo,
			Tag:       tag,
			URI:       repoURI,
			ImageType: imageType,
			Created:   createdDate,
		}

		result.Repositories = append(result.Repositories, rp)
	}

	// Execute the template.
	var buf bytes.Buffer
	if err := rc.tmpl.ExecuteTemplate(&buf, "tags", result); err != nil {
		return nil, fmt.Errorf("template rendering failed: %v", err)
	}

	return buf.Bytes(), nil
}

func (rc *registryController) vulnerabilitiesHandler(c echo.Context) error {
	logrus.WithFields(logrus.Fields{
		"func":   "vulnerabilities",
		"URL":    c.Request().URL,
		"method": c.Request().Method,
	}).Info("fetching vulnerabilities")

	// Parse the query variables.
	repo, err := url.QueryUnescape(c.Param("repo"))
	tag := c.Param("tag")

	if err != nil || repo == "" {
		return c.String(http.StatusNotFound, "Empty repo")
	}

	if tag == "" {
		return c.String(http.StatusNotFound, "Empty tag")
	}

	image, err := registry.ParseImage(rc.reg.Domain + "/" + repo + ":" + tag)
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"func":   "vulnerabilities",
			"URL":    c.Request().URL,
			"method": c.Request().Method,
		}).Errorf("parsing image %s:%s failed: %v", repo, tag, err)
		return c.String(http.StatusInternalServerError, fmt.Sprintf("Parsing image %s:%s failed", repo, tag))
	}

	// Get the vulnerability report.
	result, err := rc.cl.VulnerabilitiesV3(context.TODO(), rc.reg, image.Path, image.Reference())
	if err != nil {
		// Fallback to Clair v2 API.
		result, err = rc.cl.Vulnerabilities(context.TODO(), rc.reg, image.Path, image.Reference())
		if err != nil {
			logrus.WithFields(logrus.Fields{
				"func":   "vulnerabilities",
				"URL":    c.Request().URL,
				"method": c.Request().Method,
			}).Errorf("vulnerability scanning for %s:%s failed: %v", repo, tag, err)
			return c.String(http.StatusInternalServerError, fmt.Sprintf("Vulnerability scanning for %s:%s failed", repo, tag))
		}
	}

	if strings.HasSuffix(c.Request().URL.String(), ".json") {
		return c.JSON(http.StatusOK, result)
	}

	// Execute the template.
	if err := rc.tmpl.ExecuteTemplate(c.Response().Writer, "vulns", result); err != nil {
		logrus.WithFields(logrus.Fields{
			"func":   "vulnerabilities",
			"URL":    c.Request().URL,
			"method": c.Request().Method,
		}).Errorf("template rendering failed: %v", err)
		return c.String(http.StatusInternalServerError, fmt.Sprintf("template rendering failed: %v", err))
	}
	return nil
}
