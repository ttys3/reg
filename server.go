package main

import (
	"context"
	"embed"
	"flag"
	"fmt"
	"html/template"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/dustin/go-humanize"
	"github.com/genuinetools/reg/clair"
	"github.com/labstack/echo/v4"
	wordwrap "github.com/mitchellh/go-wordwrap"
	"github.com/sirupsen/logrus"
)

const serverHelp = `Run a static UI server for a registry.`

var (
	//go:embed server
	assets embed.FS
)

func (cmd *serverCommand) Name() string      { return "server" }
func (cmd *serverCommand) Args() string      { return "[OPTIONS]" }
func (cmd *serverCommand) ShortHelp() string { return serverHelp }
func (cmd *serverCommand) LongHelp() string  { return serverHelp }
func (cmd *serverCommand) Hidden() bool      { return false }

func (cmd *serverCommand) Register(fs *flag.FlagSet) {
	fs.DurationVar(&cmd.interval, "interval", time.Hour, "interval to generate new index.html's at")

	fs.StringVar(&cmd.registryServer, "registry", "", "URL to the private registry (ex. r.j3ss.co)")
	fs.StringVar(&cmd.registryServer, "r", "", "URL to the private registry (ex. r.j3ss.co)")

	fs.StringVar(&cmd.clairServer, "clair", "", "url to clair instance")

	fs.StringVar(&cmd.cert, "cert", "", "path to ssl cert")
	fs.StringVar(&cmd.key, "key", "", "path to ssl key")
	fs.StringVar(&cmd.listenAddress, "addr", "", "address to listen on")
	fs.StringVar(&cmd.port, "port", "8080", "port for server to run on")
	fs.StringVar(&cmd.assetPath, "asset-path", "", "Path to assets and templates")

	fs.BoolVar(&cmd.generateAndExit, "once", false, "generate the templates once and then exit")
}

type serverCommand struct {
	interval       time.Duration
	registryServer string
	clairServer    string

	generateAndExit bool

	cert          string
	key           string
	listenAddress string
	port          string
	assetPath     string
}

func traverseDirFunc(subFs embed.FS, dir string, results *[]string) {
	if files, err := subFs.ReadDir(dir); err == nil {
		for _, f := range files {
			if f.Name() == "." || f.Name() == ".." {
				continue
			}
			if !f.IsDir() {
				*results = append(*results, filepath.Join(dir, f.Name()))
			} else {
				traverseDirFunc(subFs, filepath.Join(dir, f.Name()), results)
			}
		}
	} else {
		logrus.Error(err)
	}
}

func (cmd *serverCommand) Run(ctx context.Context, args []string) error {
	// Create the registry client.
	r, err := createRegistryClient(ctx, cmd.registryServer)
	if err != nil {
		return err
	}

	// Create the registry controller for the handlers.
	rc := registryController{
		reg:          r,
		generateOnly: cmd.generateAndExit,
	}

	// Create a clair client if the user passed in a server address.
	if len(cmd.clairServer) > 0 {
		rc.cl, err = clair.New(cmd.clairServer, clair.Opt{
			Insecure: insecure,
			Debug:    debug,
			Timeout:  timeout,
		})
		if err != nil {
			return fmt.Errorf("creation of clair client at %s failed: %v", cmd.clairServer, err)
		}
	} else {
		rc.cl = nil
	}
	// Get the path to the asset directory.
	assetDir := cmd.assetPath
	if len(cmd.assetPath) <= 0 {
		assetDir, err = os.Getwd()
		if err != nil {
			return err
		}
	}

	staticDir := filepath.Join(assetDir, "static")

	if debug {
		logrus.Info("beginning to traverse assets")
		logrus.Info("--------------------------------------")
		results := []string{}

		traverseDirFunc(assets, ".", &results)
		for _, f := range results {
			logrus.Infof("file: %s", f)
		}
		logrus.Info("--------------------------------------")
	}

	funcMap := template.FuncMap{
		"trim": func(s string) string {
			return wordwrap.WrapString(s, 80)
		},
		"color": func(s string) string {
			switch s = strings.ToLower(s); s {
			case "high":
				return "danger"
			case "critical":
				return "danger"
			case "defcon1":
				return "danger"
			case "medium":
				return "warning"
			case "low":
				return "info"
			case "negligible":
				return "info"
			case "unknown":
				return "default"
			default:
				return "default"
			}
		},
		"humanize_bytes": func(s int64) string {
			return humanize.Bytes(uint64(s))
		},
	}

	rc.tmpl = template.New("").Funcs(funcMap)
	rc.tmpl, err = rc.tmpl.ParseFS(assets, "server/templates/*.html")
	if err != nil {
		return fmt.Errorf("parsing templates failed: %v", err)
	}

	// Create the initial index.
	logrus.Info("creating initial static index")
	if err := rc.repositories(ctx, staticDir); err != nil {
		return fmt.Errorf("creating index failed: %v", err)
	}

	if cmd.generateAndExit {
		logrus.Info("output generated, exiting...")
		return nil
	}

	rc.interval = cmd.interval
	ticker := time.NewTicker(rc.interval)
	go func() {
		// Create more indexes every X minutes based off interval.
		for range ticker.C {
			logrus.Info("creating timer based static index")
			if err := rc.repositories(ctx, staticDir); err != nil {
				logrus.Warnf("creating static index failed: %v", err)
			}
		}
	}()

	e := echo.New()
	//// Create mux server.
	//mux := mux.NewRouter()
	// UseEncodedPath tells the router to match the encoded original path
	// to the routes.
	// For eg. "/path/foo%2Fbar/to" will match the path "/path/{var}/to".
	//
	// If not called, the router will match the unencoded path to the routes.
	// For eg. "/path/foo%2Fbar/to" will match the path "/path/foo/bar/to"
	//mux.UseEncodedPath()

	// Static files handler.
	e.GET("/repo/:repo/tags", rc.tagsHandler)
	e.GET("/repo/:repo/tags/", rc.tagsHandler)
	e.GET("/repo/:repo/tag/:tag", rc.vulnerabilitiesHandler)
	e.GET("/repo/:repo/tag/:tag/", rc.vulnerabilitiesHandler)

	// Add the vulns endpoints if we have a client for a clair server.
	if rc.cl != nil {
		logrus.Infof("adding clair handlers...")
		e.GET("/repo/:repo/tag/:tag/vulns", rc.vulnerabilitiesHandler)
		e.GET("/repo/:repo/tag/:tag/vulns/", rc.vulnerabilitiesHandler)
		e.GET("/repo/:repo/tag/:tag/vulns.json", rc.vulnerabilitiesHandler)
	}

	// while request uri path is: /static/css/styles.css
	// the file path in embed FS is: server/static/css/styles.css
	// we need a Sub FS to strip the path prefix (here it is "server") when Open the file
	assetSubFS, _ := fs.Sub(assets, "server")
	// Serve the static assets.
	staticAssetsHandler := http.FileServer(http.FS(assetSubFS))
	e.GET("/static/*", echo.WrapHandler(staticAssetsHandler))

	//e.GET("/static/*", echo.WrapHandler(http.StripPrefix("/static/", staticAssetsHandler)))

	staticHandler := http.FileServer(http.Dir(staticDir))

	e.GET("/", echo.WrapHandler(staticHandler))

	// Set up the server.
	logrus.Infof("Starting server on port %q", cmd.port)
	if len(cmd.cert) > 0 && len(cmd.key) > 0 {
		return e.StartTLS(cmd.listenAddress+":"+cmd.port, cmd.cert, cmd.key)
	}
	return e.Start(cmd.listenAddress + ":" + cmd.port)
}
