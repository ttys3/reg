package registry

import (
	"context"
	"github.com/opencontainers/go-digest"
	"github.com/sirupsen/logrus"
	"time"
)

type tagsResponse struct {
	Tags []string `json:"tags"`
}

// Tags returns the tags for a specific repository.
func (r *Registry) Tags(ctx context.Context, repository string) ([]string, error) {
	url := r.url("/v2/%s/tags/list", repository)
	r.Logf("registry.tags url=%s repository=%s", url, repository)

	var response tagsResponse
	if _, err := r.getJSON(ctx, url, &response); err != nil {
		return nil, err
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
