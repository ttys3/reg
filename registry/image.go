package registry

import (
	"fmt"
	"time"

	"github.com/distribution/reference"
	digest "github.com/opencontainers/go-digest"
)

// Image holds information about an image.
type Image struct {
	Domain string
	Path   string
	Tag    string
	Digest digest.Digest
	named  reference.Named
}

type Layer struct {
	Index       int64 // start from 1
	Digest      digest.Digest
	Size        int64
	Command     string
	CommandLang string
	Created     *time.Time
}

// String returns the string representation of an image.
func (i Image) String() string {
	return i.named.String()
}

// Reference returns either the digest if it is non-empty or the tag for the image.
func (i Image) Reference() string {
	if len(i.Digest.String()) > 1 {
		return i.Digest.String()
	}

	return i.Tag
}

// WithDigest sets the digest for an image.
func (i *Image) WithDigest(digest digest.Digest) (err error) {
	i.Digest = digest
	i.named, err = reference.WithDigest(i.named, digest)
	return err
}

// ParseImage returns an Image struct with all the values filled in for a given image.
func ParseImage(image string) (Image, error) {
	// Parse the image name and tag.
	named, err := reference.ParseNormalizedNamed(image)
	if err != nil {
		return Image{}, fmt.Errorf("parsing image %q failed: %v", image, err)
	}
	// Add the latest lag if they did not provide one.
	named = reference.TagNameOnly(named)

	i := Image{
		named:  named,
		Domain: reference.Domain(named),
		Path:   reference.Path(named),
	}

	// Add the tag if there was one.
	if tagged, ok := named.(reference.Tagged); ok {
		i.Tag = tagged.Tag()
	}

	// Add the digest if there was one.
	if canonical, ok := named.(reference.Canonical); ok {
		i.Digest = canonical.Digest()
	}

	return i, nil
}
