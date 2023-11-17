package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"

	"github.com/ttys3/reg/registry"
)

const manifestHelp = `Get the json manifest for a repository.`

func (cmd *manifestCommand) Name() string      { return "manifest" }
func (cmd *manifestCommand) Args() string      { return "[OPTIONS] NAME[:TAG|@DIGEST]" }
func (cmd *manifestCommand) ShortHelp() string { return manifestHelp }
func (cmd *manifestCommand) LongHelp() string  { return manifestHelp }
func (cmd *manifestCommand) Hidden() bool      { return false }

func (cmd *manifestCommand) Register(fs *flag.FlagSet) {
	fs.BoolVar(&cmd.oci, "oci", false, "force the version of the manifest retrieved to oci (default is v2)")
}

type manifestCommand struct {
	oci bool
}

func (cmd *manifestCommand) Run(ctx context.Context, args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("pass the name of the repository")
	}

	image, err := registry.ParseImage(args[0])
	if err != nil {
		return err
	}

	// Create the registry client.
	r, err := createRegistryClient(ctx, image.Domain)
	if err != nil {
		return err
	}

	var manifest interface{}
	if cmd.oci {
		// Get the oci manifest if it was explicitly asked for.
		manifest, err = r.ManifestOCI(ctx, image.Path, image.Reference())
		if err != nil {
			return err
		}
	} else {
		// Get the v2 manifest.
		manifest, _, err = r.Manifest(ctx, image.Path, image.Reference())
		if err != nil {
			return err
		}
	}

	b, err := json.MarshalIndent(manifest, " ", "  ")
	if err != nil {
		return err
	}

	fmt.Println(string(b))
	return nil
}
