package registry

import (
	"context"
	"fmt"
	"net/http"

	"github.com/distribution/distribution/v3/manifest/schema2"
	digest "github.com/opencontainers/go-digest"
)

// Digest returns the digest for an image.
func (r *Registry) Digest(ctx context.Context, image Image) (digest.Digest, error) {
	if len(image.Digest) > 1 {
		// return early if we already have an image digest.
		return image.Digest, nil
	}

	url := r.url("/v2/%s/manifests/%s", image.Path, image.Tag)
	r.Logf("registry.manifests.get url=%s repository=%s ref=%s",
		url, image.Path, image.Tag)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", err
	}

	req.Header.Add("Accept", schema2.MediaTypeManifest)
	resp, err := r.Client.Do(req.WithContext(ctx))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNotFound {
		return "", fmt.Errorf("got status code: %d", resp.StatusCode)
	}

	return digest.Parse(resp.Header.Get("Docker-Content-Digest"))
}
