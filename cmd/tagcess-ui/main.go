// Command tagcess-ui serves the tagcess interface on fixed sample data, for looking at and
// screenshotting pages without Zitadel, Headscale or a database (docs/ui-guide.md). It is a
// development tool only: it has no authentication and must not be deployed.
package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"time"

	"github.com/nesiler/tagcess/internal/version"
	"github.com/nesiler/tagcess/internal/web"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:8770", "listen address (loopback only)")
	showVersion := flag.Bool("version", false, "print the version and exit")
	flag.Parse()
	if *showVersion {
		fmt.Println(version.String("tagcess-ui"))
		return
	}
	host, _, err := net.SplitHostPort(*addr)
	if err != nil {
		log.Fatal(err)
	}
	if ip := net.ParseIP(host); host != "localhost" && (ip == nil || !ip.IsLoopback()) {
		log.Fatalf("tagcess-ui: %s is not a loopback address; the preview has no authentication", *addr)
	}
	srv := &http.Server{Addr: *addr, Handler: web.PreviewHandler(), ReadHeaderTimeout: 5 * time.Second}
	log.Printf("tagcess-ui: http://%s/_ui", *addr)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}
