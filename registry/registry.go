package registry

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/distribution/distribution/v3/manifest/ocischema"
	ociv1 "github.com/opencontainers/image-spec/specs-go/v1"
	"io"
	"log"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/distribution/distribution/v3/manifest/manifestlist"
	"github.com/distribution/distribution/v3/manifest/schema2"
	"github.com/docker/docker/api/types"
)

var ErrResourceNotFound = errors.New("resource not found")
var ErrBadRequest = errors.New("bad request")
var ErrUnexpectedHttpStatusCode = errors.New("unexpected http status code")

// Registry defines the client for retrieving information from the registry API.
type Registry struct {
	URL        string
	Domain     string
	Username   string
	Password   string
	Client     *http.Client
	PingClient *http.Client
	Logf       LogfCallback
	Opt        Opt
}

var reProtocol = regexp.MustCompile("^https?://")

// LogfCallback is the callback for formatting logs.
type LogfCallback func(format string, args ...interface{})

// Quiet discards logs silently.
func Quiet(format string, args ...interface{}) {}

// Log passes log messages to the logging package.
func Log(format string, args ...interface{}) {
	log.Printf(format, args...)
}

// Opt holds the options for a new registry.
type Opt struct {
	Domain   string
	Insecure bool
	Debug    bool
	SkipPing bool
	NonSSL   bool
	Timeout  time.Duration
	Headers  map[string]string
}

// New creates a new Registry struct with the given URL and credentials.
func New(ctx context.Context, auth types.AuthConfig, opt Opt) (*Registry, error) {
	transport := http.DefaultTransport

	if opt.Insecure {
		transport = &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		}
	}

	return newFromTransport(ctx, auth, transport, opt)
}

func newFromTransport(ctx context.Context, auth types.AuthConfig, transport http.RoundTripper, opt Opt) (*Registry, error) {
	if len(opt.Domain) < 1 || opt.Domain == "docker.io" {
		opt.Domain = auth.ServerAddress
	}
	url := strings.TrimSuffix(opt.Domain, "/")
	authURL := strings.TrimSuffix(auth.ServerAddress, "/")

	if !reProtocol.MatchString(url) {
		if !opt.NonSSL {
			url = "https://" + url
		} else {
			url = "http://" + url
		}
	}

	if !reProtocol.MatchString(authURL) {
		if !opt.NonSSL {
			authURL = "https://" + authURL
		} else {
			authURL = "http://" + authURL
		}
	}

	tokenTransport := &TokenTransport{
		Transport: transport,
		Username:  auth.Username,
		Password:  auth.Password,
	}
	basicAuthTransport := &BasicTransport{
		Transport: tokenTransport,
		URL:       authURL,
		Username:  auth.Username,
		Password:  auth.Password,
	}
	errorTransport := &ErrorTransport{
		Transport: basicAuthTransport,
	}
	customTransport := &CustomTransport{
		Transport: errorTransport,
		Headers:   opt.Headers,
	}

	// set the logging
	logf := Quiet
	if opt.Debug {
		logf = Log
	}

	registry := &Registry{
		URL:    url,
		Domain: reProtocol.ReplaceAllString(url, ""),
		Client: &http.Client{
			Timeout:   opt.Timeout,
			Transport: customTransport,
		},
		PingClient: &http.Client{
			Timeout: opt.Timeout,
			Transport: &CustomTransport{
				Transport: transport,
				Headers:   opt.Headers,
			},
		},
		Username: auth.Username,
		Password: auth.Password,
		Logf:     logf,
		Opt:      opt,
	}

	if registry.Pingable() && !opt.SkipPing {
		if err := registry.Ping(ctx); err != nil {
			return nil, err
		}
	}

	return registry, nil
}

// url returns a registry URL with the passed arguements concatenated.
func (r *Registry) url(pathTemplate string, args ...interface{}) string {
	pathSuffix := fmt.Sprintf(pathTemplate, args...)
	url := fmt.Sprintf("%s%s", r.URL, pathSuffix)
	return url
}

func (r *Registry) getJSON(ctx context.Context, url string, response interface{}) (http.Header, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}

	switch response.(type) {
	case *ocischema.Manifest:
		req.Header.Add("Accept", fmt.Sprintf("%s,%s", schema2.MediaTypeManifest, ociv1.MediaTypeImageManifest))
	case *schema2.Manifest:
		// https://docs.docker.com/registry/spec/manifest-v2-2/#backward-compatibility
		// When pulling images, clients indicate support for this new version of the manifest format
		// by sending the `application/vnd.docker.distribution.manifest.v2+json` and
		// `application/vnd.docker.distribution.manifest.list.v2+json` media types in an `Accept` header
		// when making a request to the `manifests` endpoint. Updated clients should check
		// the `Content-Type` header to see whether the manifest returned from the endpoint is in the old format,
		// or is an image manifest or manifest list in the new format.
		req.Header.Add("Accept", fmt.Sprintf("%s,%s", schema2.MediaTypeManifest, ociv1.MediaTypeImageManifest))
	case *manifestlist.ManifestList:
		req.Header.Add("Accept", fmt.Sprintf("%s,%s", manifestlist.MediaTypeManifestList, ociv1.MediaTypeImageIndex))
	}

	resp, err := r.Client.Do(req.WithContext(ctx))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	r.Logf("registry.registry resp.Status=%s content_type=%s", resp.Status, resp.Header.Get("Content-Type"))

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		var wrapErr error
		switch resp.StatusCode {
		case http.StatusBadRequest:
			wrapErr = ErrBadRequest
			// 404: resource not found, body={"errors":[{"code":"MANIFEST_UNKNOWN","message":"OCI manifest found, but accept header does not support OCI manifests"}]}
		case http.StatusNotFound:
			wrapErr = ErrResourceNotFound
		default:
			wrapErr = ErrUnexpectedHttpStatusCode
		}
		if resp.StatusCode == http.StatusNotFound {
			wrapErr = ErrResourceNotFound
		}
		return nil, fmt.Errorf("%v: %w, body=%s", resp.StatusCode, wrapErr, string(body))
	}

	if err := json.NewDecoder(resp.Body).Decode(response); err != nil {
		return nil, err
	}

	return resp.Header, nil
}
