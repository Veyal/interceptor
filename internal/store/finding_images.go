package store

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
)

// PutImageBytes stores screenshot/evidence bytes in the content-addressed bodies
// directory (same layout as flow bodies) and returns the sha256 hash. MIME is
// sanitized to the notes raster allowlist. Max size matches notes images (5 MiB).
func (s *Store) PutImageBytes(mime string, data []byte) (hash string, n int64, err error) {
	if len(data) == 0 {
		return "", 0, fmt.Errorf("empty image")
	}
	if len(data) > maxNotesImageBytes {
		return "", 0, fmt.Errorf("image too large (max %d bytes)", maxNotesImageBytes)
	}
	w, err := s.NewBodyWriter()
	if err != nil {
		return "", 0, err
	}
	if _, err := w.Write(data); err != nil {
		w.Abort()
		return "", 0, err
	}
	return w.Finalize()
}

// BodyExists reports whether a content-addressed body file is present on disk.
func (s *Store) BodyExists(hash string) bool {
	if !isContentHash(hash) {
		return false
	}
	_, err := os.Stat(s.bodyPath(hash))
	return err == nil
}

// AttachImage inserts (or updates) an image block in the finding's narrative body.
// hash must already be stored via PutImageBytes. pos is the 0-based block index;
// pass -1 to append. Idempotent on the same hash — updates mime/caption in place.
func (s *Store) AttachImage(findingID int64, hash, mime, caption string, pos int) error {
	if !isContentHash(hash) {
		return fmt.Errorf("invalid image hash")
	}
	if !s.BodyExists(hash) {
		return fmt.Errorf("image blob not found")
	}
	mime = SanitizeNotesImageMIME(mime)
	caption = strings.TrimSpace(caption)

	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	var bodyJSON string
	if err := tx.QueryRow(`SELECT body FROM findings WHERE id=?`, findingID).Scan(&bodyJSON); err != nil {
		return err
	}
	newBody := insertImageIntoBody(bodyJSON, hash, mime, caption, pos)
	detailSync := firstTextMD(newBody)
	if _, err := tx.Exec(
		`UPDATE findings SET body=?, detail=CASE WHEN ?<>'' THEN ? ELSE detail END, updated_ts=? WHERE id=?`,
		newBody, detailSync, detailSync, time.Now().UnixMilli(), findingID); err != nil {
		return err
	}
	return tx.Commit()
}

// insertImageIntoBody inserts an image block at position pos. If the hash is
// already present, mime/caption are updated in place (position unchanged).
func insertImageIntoBody(bodyJSON, hash, mime, caption string, pos int) string {
	var recs []blockRecord
	if bodyJSON != "" {
		_ = json.Unmarshal([]byte(bodyJSON), &recs)
	}
	for i, r := range recs {
		if r.Type == "image" && r.Hash == hash {
			recs[i].Mime = mime
			recs[i].Caption = caption
			j, _ := json.Marshal(recs)
			return string(j)
		}
	}
	newBlock := blockRecord{Type: "image", Hash: hash, Mime: mime, Caption: caption}
	if pos < 0 || pos >= len(recs) {
		recs = append(recs, newBlock)
	} else {
		recs = append(recs, blockRecord{})
		copy(recs[pos+1:], recs[pos:])
		recs[pos] = newBlock
	}
	j, _ := json.Marshal(recs)
	return string(j)
}

// enrichImageBlocks sets URL + Missing on image blocks based on blob presence.
func (s *Store) enrichImageBlocks(blocks []FindingBlock) {
	for i := range blocks {
		if blocks[i].Type != "image" {
			continue
		}
		h := blocks[i].Hash
		if h == "" || !isContentHash(h) {
			blocks[i].Missing = true
			continue
		}
		blocks[i].URL = "/api/findings/images/" + h
		if blocks[i].Mime == "" {
			blocks[i].Mime = "application/octet-stream"
		} else {
			blocks[i].Mime = SanitizeNotesImageMIME(blocks[i].Mime)
		}
		if !s.BodyExists(h) {
			blocks[i].Missing = true
		}
	}
}

// FindingImageHashes returns every content hash referenced by image blocks in
// all findings' body JSON. Used by GCBodies so screenshot evidence is not
// deleted while still attached to a finding.
func (s *Store) FindingImageHashes() (map[string]struct{}, error) {
	out := make(map[string]struct{})
	rows, err := s.db.Query(`SELECT body FROM findings WHERE body != ''`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var body string
		if err := rows.Scan(&body); err != nil {
			return nil, err
		}
		var recs []blockRecord
		if err := json.Unmarshal([]byte(body), &recs); err != nil {
			continue
		}
		for _, r := range recs {
			if r.Type == "image" && isContentHash(r.Hash) {
				out[r.Hash] = struct{}{}
			}
		}
	}
	return out, rows.Err()
}

// FindingImageMIME returns the MIME stored on the first finding image block
// that references hash, or "" if none.
func (s *Store) FindingImageMIME(hash string) string {
	if !isContentHash(hash) {
		return ""
	}
	rows, err := s.db.Query(`SELECT body FROM findings WHERE body LIKE ?`, "%"+hash+"%")
	if err != nil {
		return ""
	}
	defer rows.Close()
	for rows.Next() {
		var body string
		if err := rows.Scan(&body); err != nil {
			return ""
		}
		var recs []blockRecord
		if err := json.Unmarshal([]byte(body), &recs); err != nil {
			continue
		}
		for _, r := range recs {
			if r.Type == "image" && r.Hash == hash {
				return SanitizeNotesImageMIME(r.Mime)
			}
		}
	}
	return ""
}
