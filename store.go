package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode"
)

// User is who made a request, as reported by Tailscale.
type User struct {
	Login string `json:"login"`
	Name  string `json:"name"`
	Pic   string `json:"pic,omitempty"`
}

// FileMeta describes one shared item. A file's body lives in blobs/<ID>; a
// folder (e.g. a Logic Pro .logicx project) is the directory blobs/<ID>/.
type FileMeta struct {
	ID         string    `json:"id"`
	Name       string    `json:"name"`
	Size       int64     `json:"size"`
	Folder     bool      `json:"folder,omitempty"`
	Count      int       `json:"count,omitempty"` // files inside a folder
	Uploader   User      `json:"uploader"`
	UploadedAt time.Time `json:"uploadedAt"`
	Scan       string    `json:"scan"`             // see scanner.go
	Threat     string    `json:"threat,omitempty"` // malware signature, if found
}

var errNoSpace = errors.New("not enough free disk space")

// Store keeps file bodies on disk and their metadata in index.json.
type Store struct {
	dir      string
	reserve  uint64 // bytes of disk to always leave free
	scanning bool   // new items start as scanPending rather than scanOff

	mu    sync.Mutex
	files map[string]*FileMeta
}

func OpenStore(dir string, reserve uint64) (*Store, error) {
	for _, sub := range []string{"blobs", "tmp"} {
		if err := os.MkdirAll(filepath.Join(dir, sub), 0o750); err != nil {
			return nil, err
		}
	}
	// Leftovers from uploads interrupted by a crash or restart.
	tmps, _ := filepath.Glob(filepath.Join(dir, "tmp", "*"))
	for _, t := range tmps {
		os.RemoveAll(t)
	}

	s := &Store{dir: dir, reserve: reserve, files: map[string]*FileMeta{}}
	data, err := os.ReadFile(filepath.Join(dir, "index.json"))
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	var list []*FileMeta
	if err := json.Unmarshal(data, &list); err != nil {
		return nil, err
	}
	for _, f := range list {
		s.files[f.ID] = f
	}
	return s, nil
}

// save writes the index atomically. Callers must hold s.mu.
func (s *Store) save() error {
	list := make([]*FileMeta, 0, len(s.files))
	for _, f := range s.files {
		list = append(list, f)
	}
	data, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}
	tmp := filepath.Join(s.dir, "index.json.tmp")
	if err := os.WriteFile(tmp, data, 0o640); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(s.dir, "index.json"))
}

// List returns all files, newest first.
func (s *Store) List() []FileMeta {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]FileMeta, 0, len(s.files))
	for _, f := range s.files {
		out = append(out, *f)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].UploadedAt.After(out[j].UploadedAt) })
	return out
}

func (s *Store) Get(id string) (FileMeta, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f, ok := s.files[id]
	if !ok {
		return FileMeta{}, false
	}
	return *f, true
}

func (s *Store) BlobPath(id string) string {
	return filepath.Join(s.dir, "blobs", id)
}

// Add streams r to disk and records it. It refuses to eat into the reserve.
func (s *Store) Add(r io.Reader, name string, u User) (FileMeta, error) {
	free := s.Free()
	if free <= s.reserve {
		return FileMeta{}, errNoSpace
	}
	allowed := int64(free - s.reserve)

	tmp, err := os.CreateTemp(filepath.Join(s.dir, "tmp"), "upload-*")
	if err != nil {
		return FileMeta{}, err
	}
	defer os.Remove(tmp.Name()) // no-op once renamed

	n, err := copyLimited(tmp, r, allowed)
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return FileMeta{}, err
	}

	f := &FileMeta{ID: newID(), Name: name, Size: n, Uploader: u, UploadedAt: time.Now().UTC()}
	if err := os.Rename(tmp.Name(), s.BlobPath(f.ID)); err != nil {
		return FileMeta{}, err
	}
	return s.record(f)
}

// record adds f to the index, undoing the blob if the index can't be saved.
func (s *Store) record(f *FileMeta) (FileMeta, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f.Scan = scanOff
	if s.scanning {
		f.Scan = scanPending
	}
	s.files[f.ID] = f
	if err := s.save(); err != nil {
		delete(s.files, f.ID)
		os.RemoveAll(s.BlobPath(f.ID))
		return FileMeta{}, err
	}
	return *f, nil
}

// copyLimited copies r to w, failing with errNoSpace past allowed bytes.
func copyLimited(w io.Writer, r io.Reader, allowed int64) (int64, error) {
	// Read one byte past the allowance so we can tell "exactly fits" from "too big".
	n, err := io.Copy(w, io.LimitReader(r, allowed+1))
	if err == nil && n > allowed {
		err = errNoSpace
	}
	return n, err
}

// FolderUpload collects one uploaded folder under tmp/ until Commit, so a
// half-uploaded Logic project never shows up in the list.
type FolderUpload struct {
	s       *Store
	id      string
	root    string
	allowed int64
	size    int64
	count   int
}

func (s *Store) NewFolder() (*FolderUpload, error) {
	free := s.Free()
	if free <= s.reserve {
		return nil, errNoSpace
	}
	id := newID()
	root := filepath.Join(s.dir, "tmp", "folder-"+id)
	if err := os.Mkdir(root, 0o750); err != nil {
		return nil, err
	}
	return &FolderUpload{s: s, id: id, root: root, allowed: int64(free - s.reserve)}, nil
}

// path resolves a client-supplied relative path inside the folder, refusing
// anything that would escape it.
func (fu *FolderUpload) path(rel string) (string, error) {
	var parts []string
	for _, p := range strings.Split(strings.ReplaceAll(rel, "\\", "/"), "/") {
		p = cleanSegment(p)
		if p == "" || p == "." || p == ".." {
			continue
		}
		parts = append(parts, p)
	}
	if len(parts) == 0 {
		return "", fmt.Errorf("%w: empty path", errBadUpload)
	}
	return filepath.Join(append([]string{fu.root}, parts...)...), nil
}

func (fu *FolderUpload) Mkdir(rel string) error {
	p, err := fu.path(rel)
	if err != nil {
		return err
	}
	return os.MkdirAll(p, 0o750)
}

func (fu *FolderUpload) Write(rel string, r io.Reader) error {
	p, err := fu.path(rel)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
		return err
	}
	out, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o640)
	if errors.Is(err, os.ErrExist) {
		return fmt.Errorf("%w: duplicate path %q", errBadUpload, rel)
	}
	if err != nil {
		return err
	}
	n, err := copyLimited(out, r, fu.allowed-fu.size)
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	fu.size += n
	fu.count++
	return err
}

func (fu *FolderUpload) Commit(name string, u User) (FileMeta, error) {
	if err := os.Rename(fu.root, fu.s.BlobPath(fu.id)); err != nil {
		fu.Abort()
		return FileMeta{}, err
	}
	f := &FileMeta{ID: fu.id, Name: name, Size: fu.size, Folder: true, Count: fu.count, Uploader: u, UploadedAt: time.Now().UTC()}
	return fu.s.record(f)
}

func (fu *FolderUpload) Abort() { os.RemoveAll(fu.root) }

func (s *Store) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.files[id]; !ok {
		return os.ErrNotExist
	}
	delete(s.files, id)
	if err := s.save(); err != nil {
		return err
	}
	return os.RemoveAll(s.BlobPath(id))
}

// Used is the total size of all shared files.
func (s *Store) Used() int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	var total int64
	for _, f := range s.files {
		total += f.Size
	}
	return total
}

// Free is the disk space available to new uploads, before the reserve.
func (s *Store) Free() uint64 {
	var st syscall.Statfs_t
	if err := syscall.Statfs(s.dir, &st); err != nil {
		return 0
	}
	return uint64(st.Bavail) * uint64(st.Bsize)
}

// cleanSegment strips control characters from one path segment and caps its length.
func cleanSegment(s string) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, s)
	if len(s) > 255 {
		ext := filepath.Ext(s)
		s = s[:255-len(ext)] + ext
	}
	return s
}

func newID() string {
	b := make([]byte, 12)
	rand.Read(b)
	return hex.EncodeToString(b)
}
