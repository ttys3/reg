package registry

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"github.com/docker/distribution"
	"github.com/docker/distribution/manifest/ocischema"
	"io/ioutil"
	"net/http"

	"github.com/distribution/distribution/v3/manifest/manifestlist"
	"github.com/distribution/distribution/v3/manifest/schema1"
	"github.com/distribution/distribution/v3/manifest/schema2"
)

var (
	// ErrUnexpectedSchemaVersion a specific schema version was requested, but was not returned
	ErrUnexpectedSchemaVersion = errors.New("recieved a different schema version than expected")
)

// Manifest returns the manifest for a specific repository:tag.
func (r *Registry) Manifest(ctx context.Context, repository, ref string) (distribution.Manifest, error) {
	uri := r.url("/v2/%s/manifests/%s", repository, ref)
	r.Logf("registry.manifests uri=%s repository=%s ref=%s", uri, repository, ref)

	req, err := http.NewRequest("GET", uri, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Add("Accept", schema2.MediaTypeManifest)

	resp, err := r.Client.Do(req.WithContext(ctx))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	r.Logf("registry.manifests resp.Status=%s, body=%s", resp.Status, body)

	m, _, err := distribution.UnmarshalManifest(resp.Header.Get("Content-Type"), body)
	if err != nil {
		return nil, err
	}

	return m, nil
}

// ManifestList gets the registry v2 manifest list.
func (r *Registry) ManifestList(ctx context.Context, repository, ref string) (manifestlist.ManifestList, error) {
	uri := r.url("/v2/%s/manifests/%s", repository, ref)
	r.Logf("registry.manifests uri=%s repository=%s ref=%s", uri, repository, ref)

	var m manifestlist.ManifestList
	if _, err := r.getJSON(ctx, uri, &m); err != nil {
		r.Logf("registry.manifests response=%v", m)
		return m, err
	}

	return m, nil
}

// ManifestOCI gets the registry OCI manifest.
// Warning: currently not supported by docker open source registry or docker hub.
func (r *Registry) ManifestOCI(ctx context.Context, repository, ref string) (ocischema.Manifest, error) {
	uri := r.url("/v2/%s/manifests/%s", repository, ref)
	r.Logf("registry.manifests uri=%s repository=%s ref=%s", uri, repository, ref)

	var m ocischema.Manifest
	if _, err := r.getJSON(ctx, uri, &m); err != nil {
		r.Logf("registry.manifests response=%v", m)
		return m, err
	}

	if m.Versioned.SchemaVersion != ocischema.SchemaVersion.SchemaVersion {
		return m, ErrUnexpectedSchemaVersion
	}

	return m, nil
}

// ManifestV2 gets the registry v2 manifest.
// v2 means "Schema 2", Image Manifest Version 2, Schema 2
// https://docs.docker.com/registry/spec/manifest-v2-2/
func (r *Registry) ManifestV2(ctx context.Context, repository, ref string) (schema2.Manifest, error) {
	uri := r.url("/v2/%s/manifests/%s", repository, ref)
	r.Logf("registry.manifests uri=%s repository=%s ref=%s", uri, repository, ref)

	var m schema2.Manifest
	if _, err := r.getJSON(ctx, uri, &m); err != nil {
		r.Logf("registry.manifests response=%v", m)
		return m, err
	}

	if m.Versioned.SchemaVersion != schema2.SchemaVersion.SchemaVersion {
		return m, ErrUnexpectedSchemaVersion
	}

	return m, nil
}

// ManifestV1 gets the registry v1 manifest.
// v1 means "Schema 1", Image Manifest Version 2, Schema 1
// https://docs.docker.com/registry/spec/manifest-v2-1/#manifest-field-descriptions
func (r *Registry) ManifestV1(ctx context.Context, repository, ref string) (schema1.SignedManifest, error) {
	uri := r.url("/v2/%s/manifests/%s", repository, ref)
	r.Logf("registry.manifests uri=%s repository=%s ref=%s", uri, repository, ref)

	var m schema1.SignedManifest
	if _, err := r.getJSON(ctx, uri, &m); err != nil {
		payload, _, _ := m.Payload()
		r.Logf("registry.manifests v1 response, Manifest=%v Canonical=%s Payload=%s", m.Manifest, m.Canonical, payload)
		return m, err
	}

	if m.Versioned.SchemaVersion != 1 {
		return m, ErrUnexpectedSchemaVersion
	}

	return m, nil
}

// PutManifest calls a PUT for the specific manifest for an image.
func (r *Registry) PutManifest(ctx context.Context, repository, ref string, manifest distribution.Manifest) error {
	url := r.url("/v2/%s/manifests/%s", repository, ref)
	r.Logf("registry.manifest.put url=%s repository=%s reference=%s", url, repository, ref)

	b, err := json.Marshal(manifest)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("PUT", url, bytes.NewBuffer(b))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", schema2.MediaTypeManifest)
	resp, err := r.Client.Do(req.WithContext(ctx))
	if resp != nil {
		defer resp.Body.Close()
	}
	return err
}
