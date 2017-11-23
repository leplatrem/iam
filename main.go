package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"

	"github.com/mozilla/doorman/doorman"
	"github.com/mozilla/doorman/utilities"
)

// DefaultPoliciesFilename is the default policies filename.
const DefaultPoliciesFilename string = "policies.yaml"

func setupRouter() (*gin.Engine, error) {
	r := gin.New()
	// Crash free (turns errors into 5XX).
	r.Use(gin.Recovery())

	// Setup logging.
	r.Use(HTTPLoggerMiddleware())

	// Setup doorman and load configuration files.
	w := doorman.New(sources())
	if err := w.LoadPolicies(); err != nil {
		return nil, err
	}

	doorman.SetupRoutes(r, w)

	utilities.SetupRoutes(r)

	return r, nil
}

func sources() []string {
	// If POLICIES not specified, read ./policies.yaml
	env := os.Getenv("POLICIES")
	if env == "" {
		env = DefaultPoliciesFilename
	}
	sources := strings.Split(env, " ")
	// Filter empty strings
	var r []string
	for _, v := range sources {
		s := strings.TrimSpace(v)
		if s != "" {
			r = append(r, s)
		}
	}
	return r
}

func main() {
	var (
		cfgFile        string
		debug, version bool
	)
	flag.StringVar(&cfgFile, "c", "policies.yaml", "Path to configuration file")
	flag.BoolVar(&version, "v", false, "Print version")
	flag.BoolVar(&version, "D", false, "Set debug")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "USAGE: doorman -c policies.yaml\n")
		fmt.Fprintf(os.Stderr, "\nCLI options\n-----------\n\n")
		fmt.Fprintf(os.Stderr, "  -c: string\n\tPath to the configuration file (default `policies.yaml`)\n")
		fmt.Fprintf(os.Stderr, "  -D:\n\tSet log level to `debug`\n")
		fmt.Fprintf(os.Stderr, "  -v:\n\tDisplay the current server version\n")
		fmt.Fprintf(os.Stderr, "  -h:\n\tDisplay this help\n")
		fmt.Fprintf(os.Stderr, "\n\nEnvironment variables\n---------------------\n\n")
		fmt.Fprintf(os.Stderr, "  POLICIES: string\n\tPath to the configuration file\n\n")
		fmt.Fprintf(os.Stderr, "  VERSION_FILE: string\n\tPath to the version file served at /__version__\n\n")
		fmt.Fprintf(os.Stderr, "  GITHUB_TOKEN: string\n\tGithub API token used to reload the config.\n\n")
		fmt.Fprintf(os.Stderr, "  LOG_LEVEL: string\n\tServer log level (one of: fatal, error, warn, debug)\n\n")
	}

	flag.Parse()

	if version {
		fmt.Printf("doorman %s\n", utilities.GetVersion())
		os.Exit(0)
	}

	if debug {
		os.Setenv("LOG_LEVEL", "debug")
	}

	env := os.Getenv("POLICIES")
	if env == "" {
		os.Setenv("POLICIES", cfgFile)
	}

	r, err := setupRouter()
	if err != nil {
		log.Fatal(err.Error())
	}
	r.Run() // listen and serve on 0.0.0.0:$PORT (:8080)
}
