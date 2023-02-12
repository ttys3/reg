package main

import (
	"bytes"
	"context"
	"fmt"
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
	ImageSize           int64                     `json:"image_size"`
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
		createdDate, imageType, imageSize, err := rc.reg.TagCreatedDate(ctx, repo, tag)
		if err != nil {
			logrus.Warnf("getting created date for %s:%s failed: %v", repo, tag, err)
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
			ImageSize: imageSize,
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

type LayerResponse struct {
	Image  *registry.Image   `json:"image"`
	Layers []*registry.Layer `json:"layer"`
}

func (rc *registryController) imageLayer(c echo.Context) error {
	logrus.WithFields(logrus.Fields{
		"func":   "layer",
		"URL":    c.Request().URL,
		"method": c.Request().Method,
	}).Info("fetching layer")

	// Parse the query variables.
	repo, err := url.QueryUnescape(c.Param("repo"))
	tag := c.Param("tag")

	if err != nil || repo == "" {
		return c.String(http.StatusNotFound, "Empty repo")
	}

	if tag == "" {
		return c.String(http.StatusNotFound, "Empty tag")
	}

	var result LayerResponse
	image, err := registry.ParseImage(rc.reg.Domain + "/" + repo + ":" + tag)
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"func":   "vulnerabilities",
			"URL":    c.Request().URL,
			"method": c.Request().Method,
		}).Errorf("parsing image %s:%s failed: %v", repo, tag, err)
		return c.String(http.StatusInternalServerError, fmt.Sprintf("Parsing image %s:%s failed", repo, tag))
	}
	result.Image = &image

	manefest, descriptor, err := rc.reg.Manifest(c.Request().Context(), repo, tag)
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"func":   "vulnerabilities",
			"URL":    c.Request().URL,
			"method": c.Request().Method,
		}).Errorf("getting manifest for %s:%s failed: %v", repo, tag, err)
		return c.String(http.StatusInternalServerError, fmt.Sprintf("Getting manifest for %s:%s failed", repo, tag))
	}

	logrus.Infof("manifest: %v, descriptor=%v", manefest, descriptor)

	layers := make([]*registry.Layer, 0, len(manefest.References()))

	for idx, ref := range manefest.References() {
		// skip the config reference
		if idx == 0 {
			continue
		}
		layers = append(layers, &registry.Layer{
			Index:       int64(idx),
			Digest:      ref.Digest,
			Size:        ref.Size,
			Command:     "",
			CommandLang: "",
			Created:     nil,
		})
	}

	theConfig := ociv1.Image{}

	err = rc.reg.GetConfig(c.Request().Context(), repo, manefest.References()[0].Digest, &theConfig)
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"func":   "layer",
			"URL":    c.Request().URL,
			"method": c.Request().Method,
		}).Errorf("getting config for %s:%s failed: %v", repo, tag, err)
		return c.String(http.StatusInternalServerError, fmt.Sprintf("Getting config for %s:%s failed", repo, tag))
	}

	historyLayerIdx := 0
	for _, layer := range theConfig.History {
		if layer.EmptyLayer {
			continue
		}

		if historyLayerIdx == len(layers) {
			logrus.Errorf("the number of layers is not equal to the number of history, layers=%d, history=%d non-empty history: %d",
				len(layers), len(theConfig.History), historyLayerIdx)
			//break
		}

		layers[historyLayerIdx].Command = layer.CreatedBy
		layers[historyLayerIdx].Created = layer.Created
		// other docker directive: `/bin/sh -c #(nop) `
		// docker RUN: `/bin/sh -c `
		// multi stage build
		// |2 PHP_EXT_BENCODE_VERSION=8.1.0RC6-fpm-bullseye TINI_VERSION=v0.19.0 /bin/sh -c set -eux; curl
		if strings.HasPrefix(layer.CreatedBy, "/bin/sh -c #(nop) ") {
			layers[historyLayerIdx].Command = strings.TrimPrefix(layer.CreatedBy, "/bin/sh -c #(nop) ")
			layers[historyLayerIdx].CommandLang = "docker"
		} else if strings.HasPrefix(layer.CreatedBy, "/bin/sh -c ") {
			layers[historyLayerIdx].Command = strings.TrimPrefix(layer.CreatedBy, "/bin/sh -c ")
			layers[historyLayerIdx].CommandLang = "bash"
		} else if strings.HasPrefix(layer.CreatedBy, "|") {
			layers[historyLayerIdx].Command = strings.Replace(layer.CreatedBy, "/bin/sh -c ", "\n", 1)
			layers[historyLayerIdx].CommandLang = "bash"
		}

		historyLayerIdx++
	}

	result.Layers = layers

	if strings.HasSuffix(c.Request().URL.String(), ".json") {
		return c.JSON(http.StatusOK, result)
	}

	// Execute the template.
	if err := rc.tmpl.ExecuteTemplate(c.Response().Writer, "layer", result); err != nil {
		logrus.WithFields(logrus.Fields{
			"func":   "layer",
			"URL":    c.Request().URL,
			"method": c.Request().Method,
		}).Errorf("template rendering failed: %v", err)
		return c.String(http.StatusInternalServerError, fmt.Sprintf("template rendering failed: %v", err))
	}
	return nil
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
