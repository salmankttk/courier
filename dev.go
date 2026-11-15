package main

import (
	"bytes"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Dev mode serves web/ straight from disk and live-reloads the browser:
// CSS changes are swapped in place, anything else reloads the page.

const reloadJS = `(() => {
  const es = new EventSource("/__dev/events");
  es.onmessage = (e) => {
    if (e.data.endsWith(".css")) {
      for (const link of document.querySelectorAll('link[rel="stylesheet"]')) {
        const url = new URL(link.href);
        url.searchParams.set("v", Date.now());
        link.href = url;
      }
    } else {
      location.reload();
    }
  };
})();`

type liveReload struct {
	dir  string
	mu   sync.Mutex
	subs map[chan string]bool
}

func newLiveReload(dir string) *liveReload {
	lr := &liveReload{dir: dir, subs: map[chan string]bool{}}
	go lr.watch()
	return lr
}

// watch polls modification times; simple, and plenty fast for a handful of files.
func (lr *liveReload) watch() {
	seen := map[string]time.Time{}
	first := true
	for {
		filepath.WalkDir(lr.dir, func(p string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}
			info, err := d.Info()
			if err != nil {
				return nil
			}
			if old, ok := seen[p]; (ok && info.ModTime().After(old)) || (!ok && !first) {
				lr.broadcast(filepath.Base(p))
			}
			seen[p] = info.ModTime()
			return nil
		})
		first = false
		time.Sleep(250 * time.Millisecond)
	}
}

func (lr *liveReload) broadcast(name string) {
	log.Printf("dev: %s changed", name)
	lr.mu.Lock()
	defer lr.mu.Unlock()
	for ch := range lr.subs {
		select {
		case ch <- name:
		default:
		}
	}
}

func (lr *liveReload) events(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	ch := make(chan string, 4)
	lr.mu.Lock()
	lr.subs[ch] = true
	lr.mu.Unlock()
	defer func() {
		lr.mu.Lock()
		delete(lr.subs, ch)
		lr.mu.Unlock()
	}()
	flusher, _ := w.(http.Flusher)
	fmt.Fprint(w, ": connected\n\n")
	flusher.Flush()
	for {
		select {
		case name := <-ch:
			fmt.Fprintf(w, "data: %s\n\n", name)
			flusher.Flush()
		case <-r.Context().Done():
			return
		}
	}
}

// devHandler wraps the app: assets come from disk uncached, and index.html
// gets the reload script injected.
func devHandler(app http.Handler, webDir string) http.Handler {
	lr := newLiveReload(webDir)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /__dev/events", lr.events)
	mux.HandleFunc("GET /__dev/reload.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/javascript")
		w.Write([]byte(reloadJS))
	})
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		html, err := os.ReadFile(filepath.Join(webDir, "index.html"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		html = bytes.Replace(html, []byte("</body>"), []byte(`<script src="/__dev/reload.js"></script></body>`), 1)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.Write(html)
	})
	mux.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/api/") {
			w.Header().Set("Cache-Control", "no-store")
		}
		app.ServeHTTP(w, r)
	}))
	return mux
}

// fakeScan stands in for ClamAV in dev mode so every scan state can be seen:
// names containing "eicar" come back infected.
func fakeScan(f FileMeta) (result, signature string) {
	time.Sleep(3 * time.Second)
	if strings.Contains(strings.ToLower(f.Name), "eicar") {
		return scanInfected, "Eicar-Test-Signature"
	}
	return scanClean, ""
}
