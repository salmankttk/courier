package main

import (
	"archive/zip"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"mime"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
)

//go:embed web
var webFS embed.FS

// App serves the Courier web UI and API.
type App struct {
	store   *Store
	scanner *Scanner // nil when scanning is off
	whois   func(*http.Request) (User, error)
	admins  map[string]bool // logins allowed to delete anyone's files
	static  fs.FS           // web UI files; the embedded copy unless in dev mode
}

func (a *App) Handler() http.Handler {
	static := a.static
	if static == nil {
		static, _ = fs.Sub(webFS, "web")
	}
	mux := http.NewServeMux()
	mux.Handle("GET /", http.FileServerFS(static))
	mux.HandleFunc("GET /api/me", a.handleMe)
	mux.HandleFunc("GET /api/files", a.handleList)
	mux.HandleFunc("POST /api/files", a.handleUpload)
	mux.HandleFunc("GET /api/files/{id}", a.handleDownload)
	mux.HandleFunc("DELETE /api/files/{id}", a.handleDelete)
	mux.HandleFunc("GET /api/stats", a.handleStats)
	return a.withIdentity(securityHeaders(mux))
}

type ctxUser struct{}

// withIdentity rejects anyone Tailscale can't identify and blocks cross-site
// writes: mutating requests must carry X-Courier, which a foreign page can't
// send without a CORS preflight we never answer.
func (a *App) withIdentity(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u, err := a.whois(r)
		if err != nil {
			http.Error(w, "unknown Tailscale user", http.StatusForbidden)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead && r.Header.Get("X-Courier") != "1" {
			http.Error(w, "missing X-Courier header", http.StatusForbidden)
			return
		}
		r.Header.Set("X-Courier-Login", u.Login)
		r.Header.Set("X-Courier-Name", u.Name)
		r.Header.Set("X-Courier-Pic", u.Pic)
		next.ServeHTTP(w, r)
	})
}

func userFrom(r *http.Request) User {
	return User{Login: r.Header.Get("X-Courier-Login"), Name: r.Header.Get("X-Courier-Name"), Pic: r.Header.Get("X-Courier-Pic")}
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'self'; img-src 'self' https: data:; style-src 'self'; script-src 'self'; frame-ancestors 'none'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}

func (a *App) handleMe(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r)
	writeJSON(w, map[string]any{"user": u, "admin": a.admins[u.Login]})
}

func (a *App) handleList(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, a.store.List())
}

func (a *App) handleStats(w http.ResponseWriter, r *http.Request) {
	free := a.store.Free()
	if free > a.store.reserve {
		free -= a.store.reserve
	} else {
		free = 0
	}
	writeJSON(w, map[string]any{"used": a.store.Used(), "free": free, "count": len(a.store.List())})
}

// handleUpload streams each file part of a multipart body straight to disk,
// so large uploads never sit in memory.
//
// Plain uploads are a series of "file" parts. A folder upload (a Logic Pro
// project, say) starts with a "folder" part naming it, followed by "dir"
// parts for each directory and a "path" + "file" pair for each file.
func (a *App) handleUpload(w http.ResponseWriter, r *http.Request) {
	mr, err := r.MultipartReader()
	if err != nil {
		http.Error(w, "expected multipart upload", http.StatusBadRequest)
		return
	}
	u := userFrom(r)
	var (
		added      []FileMeta
		folder     *FolderUpload
		folderName string
		filePath   string
	)
	fail := func(err error) {
		if folder != nil {
			folder.Abort()
		}
		switch {
		case errors.Is(err, errNoSpace):
			http.Error(w, "the server is out of space", http.StatusInsufficientStorage)
		case errors.Is(err, errBadUpload):
			http.Error(w, err.Error(), http.StatusBadRequest)
		default:
			log.Printf("upload by %s failed: %v", u.Login, err)
			http.Error(w, "upload failed", http.StatusInternalServerError)
		}
	}
	for {
		part, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			fail(err) // usually the uploader cancelled or lost connection
			return
		}
		switch part.FormName() {
		case "folder":
			if folder != nil {
				err = fmt.Errorf("%w: one folder per upload", errBadUpload)
				break
			}
			folderName = cleanName(readField(part))
			folder, err = a.store.NewFolder()
		case "dir":
			if folder == nil {
				err = fmt.Errorf("%w: dir outside a folder upload", errBadUpload)
				break
			}
			err = folder.Mkdir(readField(part))
		case "path":
			filePath = readField(part)
		case "file":
			if folder != nil {
				err = folder.Write(filePath, part)
				filePath = ""
				break
			}
			if part.FileName() == "" {
				continue
			}
			var f FileMeta
			if f, err = a.store.Add(part, cleanName(part.FileName()), u); err == nil {
				log.Printf("%s uploaded %q (%d bytes)", u.Login, f.Name, f.Size)
				added = append(added, f)
			}
		}
		if err != nil {
			fail(err)
			return
		}
	}
	if folder != nil {
		f, err := folder.Commit(folderName, u)
		if err != nil {
			fail(err)
			return
		}
		log.Printf("%s uploaded folder %q (%d files, %d bytes)", u.Login, f.Name, f.Count, f.Size)
		added = append(added, f)
	}
	if len(added) == 0 {
		http.Error(w, "no files in upload", http.StatusBadRequest)
		return
	}
	if a.scanner != nil {
		for _, f := range added {
			a.scanner.Enqueue(f.ID)
		}
	}
	writeJSON(w, added)
}

var errBadUpload = errors.New("malformed upload")

func readField(part io.Reader) string {
	b, _ := io.ReadAll(io.LimitReader(part, 4096))
	return string(b)
}

func (a *App) handleDownload(w http.ResponseWriter, r *http.Request) {
	f, ok := a.store.Get(r.PathValue("id"))
	if !ok {
		http.NotFound(w, r)
		return
	}
	switch f.Scan {
	case scanPending:
		http.Error(w, "still being scanned for malware, try again in a moment", http.StatusConflict)
		return
	case scanInfected:
		http.Error(w, "blocked: malware detected ("+f.Threat+")", http.StatusForbidden)
		return
	case scanError:
		http.Error(w, "the malware scan failed, so this file is held back", http.StatusConflict)
		return
	}
	if f.Folder {
		a.serveZip(w, f)
		return
	}
	body, err := os.Open(a.store.BlobPath(f.ID))
	if err != nil {
		http.Error(w, "file missing on disk", http.StatusInternalServerError)
		return
	}
	defer body.Close()
	ctype := mime.TypeByExtension(filepath.Ext(f.Name))
	if ctype == "" {
		ctype = "application/octet-stream"
	}
	w.Header().Set("Content-Type", ctype)
	// Always download, never render: an uploaded HTML file must not run as Courier.
	w.Header().Set("Content-Disposition", "attachment; filename*=UTF-8''"+url.PathEscape(f.Name))
	http.ServeContent(w, r, f.Name, f.UploadedAt, body) // handles Range for resumable downloads
}

// serveZip streams a folder as a zip, built on the fly so it needs no extra
// disk. Entries are stored uncompressed: fast, and audio barely compresses.
// Unzipping on a Mac restores the folder (and a .logicx opens in Logic).
func (a *App) serveZip(w http.ResponseWriter, f FileMeta) {
	root := a.store.BlobPath(f.ID)
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", "attachment; filename*=UTF-8''"+url.PathEscape(f.Name+".zip"))
	zw := zip.NewWriter(w)
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return err
		}
		hdr, err := zip.FileInfoHeader(info)
		if err != nil {
			return err
		}
		hdr.Name = path.Join(f.Name, filepath.ToSlash(rel))
		hdr.Method = zip.Store
		if d.IsDir() {
			hdr.Name += "/"
			_, err = zw.CreateHeader(hdr)
			return err
		}
		dst, err := zw.CreateHeader(hdr)
		if err != nil {
			return err
		}
		src, err := os.Open(p)
		if err != nil {
			return err
		}
		defer src.Close()
		_, err = io.Copy(dst, src)
		return err
	})
	if err == nil {
		err = zw.Close()
	}
	if err != nil {
		// Headers are already sent; the client sees a truncated zip.
		log.Printf("zip of %q failed: %v", f.Name, err)
	}
}

func (a *App) handleDelete(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r)
	f, ok := a.store.Get(r.PathValue("id"))
	if !ok {
		http.NotFound(w, r)
		return
	}
	if f.Uploader.Login != u.Login && !a.admins[u.Login] {
		http.Error(w, "you can only delete your own files", http.StatusForbidden)
		return
	}
	if err := a.store.Delete(f.ID); err != nil {
		http.Error(w, "delete failed", http.StatusInternalServerError)
		return
	}
	log.Printf("%s deleted %q", u.Login, f.Name)
	w.WriteHeader(http.StatusNoContent)
}

// cleanName keeps the original name readable while stripping paths and
// control characters.
func cleanName(name string) string {
	name = cleanSegment(filepath.Base(strings.ReplaceAll(name, "\\", "/")))
	if name == "" || name == "." || name == ".." || name == "/" {
		name = "untitled"
	}
	return name
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}
