package registry

import (
	"context"
	"github.com/distribution/distribution/v3/manifest/ocischema"
	"github.com/genuinetools/reg/repoutils"
	ociv1 "github.com/opencontainers/image-spec/specs-go/v1"
	"testing"
	"time"
)

func TestManifestOCIDockerhubWithOciAnnotations(t *testing.T) {
	username := ""
	password := ""

	registryHost := "docker.io"
	auth, err := repoutils.GetAuthConfig(username, password, registryHost)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.TODO()

	reg, err := New(ctx, auth, Opt{
		Domain:   registryHost,
		Insecure: false,
		Debug:    true,
		SkipPing: true,
		NonSSL:   false,
		Timeout:  time.Second * 6,
	})
	if err != nil {
		t.Fatal(err)
	}

	manifest, err := reg.ManifestOCI(ctx, "80x86/base-fedora", "37-minimal-amd64")
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("manifest: %+v", manifest)

	imanifest, descriptor, err := reg.Manifest(ctx, "80x86/base-fedora", "37-minimal-amd64")
	if err != nil {
		t.Fatal(err)
	}
	if descriptor.MediaType == ociv1.MediaTypeImageManifest {
		ocimanifest, ok := imanifest.(*ocischema.DeserializedManifest)
		if !ok {
			t.Fatal("ocimanifest is not ok")
		}
		if ocimanifest.Annotations == nil {
			t.Fatal("annotations is nil")
		}
		for k, v := range ocimanifest.Annotations {
			t.Logf("annotation: %s=%s", k, v)
		}
	} else {
		t.Logf("imanifest: %+v", imanifest)
	}
}
