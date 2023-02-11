package registry

import (
	"context"
	"github.com/genuinetools/reg/repoutils"
	"testing"
	"time"
)

// test ManifestOCI
func TestManifestOCI(t *testing.T) {
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

	manifest, err := reg.ManifestOCI(ctx, "library/fedora", "37")
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("manifest: %+v", manifest)
}
