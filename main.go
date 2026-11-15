// Courier is a shared drop box for everyone on your tailnet: upload a file,
// anyone with access can download it. It joins Tailscale as its own device,
// so you can share just Courier with a friend, and it learns who each
// visitor is from Tailscale instead of asking for passwords.
package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"tailscale.com/tsnet"
)

func main() {
	var (
		dataDir   = flag.String("data", "/srv/courier", "where shared files and the index live")
		hostname  = flag.String("hostname", "courier", "device name on the tailnet")
		stateDir  = flag.String("state", "", "Tailscale state directory (default <data>/tailscale)")
		port      = flag.Uint("port", 41642, "UDP port for direct Tailscale connections")
		useHTTPS  = flag.Bool("https", false, "serve HTTPS with a tailnet certificate (enable HTTPS in the Tailscale admin first)")
		admins    = flag.String("admins", "", "comma-separated logins that may delete any file")
		reserveGB = flag.Uint64("reserve-gb", 20, "disk space (GB) uploads may never use")
		scan      = flag.Bool("scan", true, "scan uploads with ClamAV (clamd) before allowing downloads")
		dev       = flag.String("dev", "", "run without Tailscale on this address (e.g. localhost:8080) for local testing")
	)
	flag.Parse()

	store, err := OpenStore(*dataDir, *reserveGB<<30)
	if err != nil {
		log.Fatalf("opening store: %v", err)
	}
	app := &App{store: store, admins: map[string]bool{}}
	var check func(FileMeta) (string, string)
	switch {
	case *dev != "":
		check = fakeScan
	case *scan && !scannerAvailable():
		log.Printf("clamdscan not found: uploads will NOT be scanned for malware")
		*scan = false
	}
	if *scan {
		store.scanning = true
		malwareLog := filepath.Join(*dataDir, "malware.log")
		app.scanner = NewScanner(store, check, func(f FileMeta, signature string) {
			// One line per detection; the server's alerting picks these up.
			line := fmt.Sprintf("%s\t%s\t%s\t%s\n", time.Now().Format(time.RFC3339), f.Uploader.Login, f.Name, signature)
			if lf, err := os.OpenFile(malwareLog, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o640); err == nil {
				lf.WriteString(line)
				lf.Close()
			}
		})
	}
	for _, a := range strings.Split(*admins, ",") {
		if a = strings.TrimSpace(a); a != "" {
			app.admins[a] = true
		}
	}

	if *dev != "" {
		app.whois = func(*http.Request) (User, error) {
			return User{Login: "dev@localhost", Name: "Local Dev"}, nil
		}
		app.admins["dev@localhost"] = true
		app.static = os.DirFS("web") // edit files and see them live
		log.Printf("dev mode with live reload: http://%s", *dev)
		log.Fatal(http.ListenAndServe(*dev, devHandler(app.Handler(), "web")))
	}

	if *stateDir == "" {
		*stateDir = filepath.Join(*dataDir, "tailscale")
	}
	srv := &tsnet.Server{
		Hostname: *hostname,
		Dir:      *stateDir,
		Port:     uint16(*port),
		Logf:     func(string, ...any) {}, // tsnet is chatty; keep only user-facing messages
		UserLogf: log.Printf,              // includes the login URL on first run
	}
	defer srv.Close()

	lc, err := srv.LocalClient()
	if err != nil {
		log.Fatal(err)
	}
	app.whois = func(r *http.Request) (User, error) {
		who, err := lc.WhoIs(r.Context(), r.RemoteAddr)
		if err != nil {
			return User{}, err
		}
		p := who.UserProfile
		if p == nil || p.LoginName == "" {
			return User{}, fmt.Errorf("no user for %s", r.RemoteAddr)
		}
		return User{Login: p.LoginName, Name: p.DisplayName, Pic: p.ProfilePicURL}, nil
	}

	plain, err := srv.Listen("tcp", ":80")
	if err != nil {
		log.Fatal(err)
	}
	if !*useHTTPS {
		log.Printf("serving on http://%s", *hostname)
		log.Fatal(http.Serve(plain, app.Handler()))
	}

	secure, err := srv.Listen("tcp", ":443")
	if err != nil {
		log.Fatal(err)
	}
	go func() {
		// Send plain-HTTP visitors to the HTTPS address.
		log.Fatal(http.Serve(plain, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "https://"+r.Host+r.URL.RequestURI(), http.StatusMovedPermanently)
		})))
	}()
	tlsLn := tls.NewListener(secure, &tls.Config{GetCertificate: lc.GetCertificate})
	log.Printf("serving on https://%s (full name shown in the Tailscale admin)", *hostname)
	log.Fatal(http.Serve(tlsLn, app.Handler()))
}
