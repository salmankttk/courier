package main

import (
	"bytes"
	"errors"
	"log"
	"os"
	"os/exec"
	"strings"
)

// Scan states for FileMeta.Scan.
const (
	scanPending  = "pending"  // not scanned yet; downloads blocked
	scanClean    = "clean"    // ClamAV found nothing
	scanPartial  = "partial"  // larger than ClamAV can fully scan; nothing found in what it read
	scanInfected = "infected" // malware found; the file was deleted
	scanError    = "error"    // scanner failed; downloads stay blocked
	scanOff      = "off"      // scanning disabled
)

// ClamAV only scans up to this much of a file.
const scanLimit = 4000 << 20

// Scanner checks uploads with ClamAV (via clamd) one at a time.
type Scanner struct {
	store   *Store
	queue   chan string
	onFound func(f FileMeta, signature string)
	check   func(f FileMeta) (result, signature string)
}

// NewScanner starts scanning with check, or with ClamAV when check is nil.
func NewScanner(store *Store, check func(FileMeta) (string, string), onFound func(FileMeta, string)) *Scanner {
	s := &Scanner{store: store, queue: make(chan string, 1024), onFound: onFound, check: check}
	if s.check == nil {
		s.check = func(f FileMeta) (string, string) { return s.clamScan(store.BlobPath(f.ID)) }
	}
	go s.run()
	// Anything left pending from before a restart, and earlier failures.
	for _, f := range store.List() {
		if f.Scan == scanPending || f.Scan == scanError {
			s.Enqueue(f.ID)
		}
	}
	return s
}

func (s *Scanner) Enqueue(id string) { s.queue <- id }

func (s *Scanner) run() {
	for id := range s.queue {
		f, ok := s.store.Get(id)
		if !ok {
			continue
		}
		result, signature := s.check(f)
		if result == scanClean && f.Size > scanLimit {
			result = scanPartial
		}
		if result == scanInfected {
			log.Printf("malware in %q from %s: %s", f.Name, f.Uploader.Login, signature)
			s.store.Quarantine(id, signature)
			if s.onFound != nil {
				s.onFound(f, signature)
			}
			continue
		}
		s.store.SetScan(id, result, "")
		if result == scanError {
			log.Printf("scan of %q failed", f.Name)
		}
	}
}

// clamScan runs clamdscan. --stream sends the bytes over clamd's socket, so
// clamd needs no access to Courier's files: with --fdpass, AppArmor rejects
// descriptors from Courier's sandboxed mount namespace.
func (s *Scanner) clamScan(path string) (result, signature string) {
	var out bytes.Buffer
	cmd := exec.Command("clamdscan", "--no-summary", "--stream", "--stdout", path)
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	var exit *exec.ExitError
	switch {
	case err == nil:
		return scanClean, ""
	case errors.As(err, &exit) && exit.ExitCode() == 1:
		// Lines look like "/path/to/file: Eicar-Signature FOUND".
		for _, line := range strings.Split(out.String(), "\n") {
			if before, ok := strings.CutSuffix(strings.TrimSpace(line), " FOUND"); ok {
				if i := strings.LastIndex(before, ": "); i >= 0 {
					return scanInfected, before[i+2:]
				}
			}
		}
		return scanInfected, "unknown"
	default:
		log.Printf("clamdscan: %v: %s", err, strings.TrimSpace(out.String()))
		return scanError, ""
	}
}

// scannerAvailable reports whether clamdscan is installed.
func scannerAvailable() bool {
	_, err := exec.LookPath("clamdscan")
	return err == nil
}

// Quarantine deletes an infected item's data but keeps its entry, marked as
// blocked, so people can see what happened.
func (s *Store) Quarantine(id, signature string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f, ok := s.files[id]
	if !ok {
		return
	}
	os.RemoveAll(s.BlobPath(id))
	f.Scan = scanInfected
	f.Threat = signature
	f.Size = 0
	s.save()
}

func (s *Store) SetScan(id, result, threat string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if f, ok := s.files[id]; ok {
		f.Scan = result
		f.Threat = threat
		s.save()
	}
}
