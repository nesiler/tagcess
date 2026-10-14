// Command tagcess-hshelper is the Headscale host helper (ADR 0008, ADR 0021). systemd starts it as
// root in three modes: `run` (the .path-triggered oneshot: take one request and apply it), `boot`
// (service start) and `finalize` (ExecStopPost). Every path and name it uses comes from flags set
// in the unit; a request carries none of them. Exit codes: 0 done, 1 runtime failure, 2 usage.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"

	"github.com/nesiler/tagcess/internal/hshelper"
	"github.com/nesiler/tagcess/internal/version"
)

var (
	unitRE = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.@-]*\.service$`)
	userRE = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)
)

// settings is the validated command line.
type settings struct {
	cfg    hshelper.Config
	health string
	socket string
}

func main() {
	os.Exit(run(os.Args[1:], os.Stderr))
}

func run(args []string, stderr io.Writer) int {
	if version.IsVersionFlag(args) {
		_, _ = fmt.Fprintln(os.Stdout, version.String("tagcess-hshelper"))
		return 0
	}
	mode, s, err := parseArgs(args)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "tagcess-hshelper: %v\nusage: tagcess-hshelper run|boot|finalize --config PATH --root DIR --unit NAME.service --service-user USER --health http://127.0.0.1:PORT/health --socket PATH --request-uid UID\n", err)
		return 2
	}
	logger := log.New(stderr, "tagcess-hshelper: ", 0)
	s.cfg.Logf = logger.Printf
	s.cfg.Projector = hshelper.NewFileProjector(s.cfg.ConfigPath)
	s.cfg.Runner = hshelper.NewSystemRunner(s.health, s.socket)

	var out hshelper.Outcome
	switch mode {
	case "run":
		out, err = hshelper.Run(s.cfg)
	case "boot":
		out, err = hshelper.Boot(s.cfg)
	case "finalize":
		out, err = hshelper.Finalize(s.cfg)
	}
	if err != nil {
		logger.Printf("%s failed: %v", mode, err)
		return 1
	}
	logger.Printf("%s: %s", mode, out)
	return 0
}

// parseArgs checks the mode and every flag. All flags are required in all modes, so one unit
// definition serves them.
func parseArgs(args []string) (string, settings, error) {
	var s settings
	if len(args) == 0 {
		return "", s, errors.New("mode required (run, boot or finalize)")
	}
	mode := args[0]
	if mode != "run" && mode != "boot" && mode != "finalize" {
		return "", s, fmt.Errorf("unknown mode %q", mode)
	}
	fs := flag.NewFlagSet(mode, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var config, root, unit, serviceUser, health, socket, uid string
	fs.StringVar(&config, "config", "", "")
	fs.StringVar(&root, "root", "", "")
	fs.StringVar(&unit, "unit", "", "")
	fs.StringVar(&serviceUser, "service-user", "", "")
	fs.StringVar(&health, "health", "", "")
	fs.StringVar(&socket, "socket", "", "")
	fs.StringVar(&uid, "request-uid", "", "")
	if err := fs.Parse(args[1:]); err != nil {
		return "", s, err
	}
	if fs.NArg() != 0 {
		return "", s, errors.New("unexpected arguments")
	}

	for _, p := range []struct{ name, val string }{{"config", config}, {"root", root}, {"socket", socket}} {
		if p.val == "" {
			return "", s, fmt.Errorf("--%s is required", p.name)
		}
		if !filepath.IsAbs(p.val) || filepath.Clean(p.val) != p.val {
			return "", s, fmt.Errorf("--%s must be a clean absolute path", p.name)
		}
	}
	switch {
	case unit == "":
		return "", s, errors.New("--unit is required")
	case !unitRE.MatchString(unit):
		return "", s, errors.New("--unit must be a plain NAME.service")
	case serviceUser == "":
		return "", s, errors.New("--service-user is required")
	case !userRE.MatchString(serviceUser) || serviceUser == "root":
		return "", s, errors.New("--service-user must be a non-root user name")
	case health == "":
		return "", s, errors.New("--health is required")
	case !validHealth(health):
		return "", s, errors.New("--health must be http://127.0.0.1:PORT/health (loopback, /health)")
	case uid == "":
		return "", s, errors.New("--request-uid is required")
	}
	n, err := strconv.ParseUint(uid, 10, 32)
	if err != nil {
		return "", s, errors.New("--request-uid must be a uid number")
	}
	s.cfg = hshelper.Config{
		Root: root, ConfigPath: config, Unit: unit, ServiceUser: serviceUser, RequestUID: uint32(n),
	}
	s.health, s.socket = health, socket
	return mode, s, nil
}

// validHealth accepts only plain http to a loopback host and port, path /health.
func validHealth(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "http" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "/health" {
		return false
	}
	switch u.Hostname() {
	case "127.0.0.1", "localhost", "::1":
	default:
		return false
	}
	_, err = strconv.ParseUint(u.Port(), 10, 16)
	return err == nil
}
