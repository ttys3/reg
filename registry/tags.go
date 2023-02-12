package registry

import (
	"context"
	"github.com/distribution/distribution/v3/manifest/ocischema"
	"github.com/distribution/distribution/v3/manifest/schema2"
	"github.com/opencontainers/go-digest"
	ociv1 "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/peterhellberg/link"
	"github.com/sirupsen/logrus"
	"net/url"
	"time"
)

type tagsResponse struct {
	Tags []string `json:"tags"`
}

// Tags returns the tags for a specific repository.
func (r *Registry) Tags(ctx context.Context, repository string) ([]string, error) {
	return r.tagsWithPagination(ctx, repository, "")
}

func (r *Registry) tagsWithPagination(ctx context.Context, repository string, u string) ([]string, error) {
	var uri string
	if u == "" {
		r.Logf("registry.tags url=%s repository=%s", u, repository)
		uri = r.url("/v2/%s/tags/list", repository)
	} else {
		uri = r.url(u)
	}

	r.Logf("registry.tags url=%s repository=%s", uri, repository)

	var response tagsResponse
	h, err := r.getJSON(ctx, uri, &response)
	if err != nil {
		return nil, err
	}

	for _, l := range link.ParseHeader(h) {
		if l.Rel == "next" {
			logrus.Infof("begin fetch next page, repo:%s, link: %s", repository, l.URI)
			unescaped, _ := url.QueryUnescape(l.URI)
			tags, err := r.tagsWithPagination(ctx, repository, unescaped)
			if err != nil {
				return nil, err
			}
			response.Tags = append(response.Tags, tags...)
		}
	}

	return response.Tags, nil
}

type configObjectBase struct {
	Created *time.Time `json:"created"`
}

func (r *Registry) CreatedDate(ctx context.Context, repository string, configDigest digest.Digest) (*time.Time, error) {
	logrus.Infof("fetching config blob for digest=%s", configDigest)
	var configBase configObjectBase
	if err := r.GetConfig(ctx, repository, configDigest, &configBase); err != nil {
		return nil, err
	}
	logrus.Infof("Got created time from config layer: %v", configBase.Created)
	return configBase.Created, nil
}

func (r *Registry) TagCreatedDate(ctx context.Context, repo, tag string) (createdDate *time.Time, imageType string, imageSize int64, retErr error) {
	imageType = "Docker v1"
	manifest, descriptor, err := r.Manifest(ctx, repo, tag)
	if err != nil {
		logrus.Errorf("getting v2 or oci manifest for %s:%s failed: %v", repo, tag, err)
		retErr = err
		return
	}

	for _, ref := range manifest.References() {
		imageSize += ref.Size
		logrus.Debugf("adding ref %s with size %d, media_type=%s", ref.Digest, ref.Size, ref.MediaType)
	}

	if descriptor.MediaType == ociv1.MediaTypeImageManifest {
		if ocimanifest, ok := manifest.(*ocischema.DeserializedManifest); ok && ocimanifest.Annotations != nil {
			if created, ok := ocimanifest.Annotations["org.opencontainers.image.created"]; ok {
				if t, err := time.Parse(time.RFC3339, created); err == nil {
					createdDate = &t
				}
			}
		}
		imageType = "OCI"
	} else if descriptor.MediaType == schema2.MediaTypeManifest {
		imageType = "Docker V2"
	}

	if createdDate == nil {
		if created, err := r.CreatedDate(ctx, repo, manifest.References()[0].Digest); err == nil {
			createdDate = created
		} else {
			logrus.Errorf("getting created time from config layer for %s:%s failed: %v", repo, tag, err)
			retErr = err
			return
		}
	}
	return
}
