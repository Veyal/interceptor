package store

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"time"
)

// APIKey is metadata for an issued control-API key. The secret token itself is
// never stored — only its SHA-256 hash and a short identifying prefix.
type APIKey struct {
	ID      int64  `json:"id"`
	Label   string `json:"label"`
	Prefix  string `json:"prefix"`
	Created int64  `json:"created"` // unix millis
}

// CreateAPIKey mints a new key, returning the full token (shown to the user
// once) and its stored metadata. The token is "ick_" + 48 hex chars.
func (s *Store) CreateAPIKey(label string) (token string, key APIKey, err error) {
	buf := make([]byte, 24)
	if _, err = rand.Read(buf); err != nil {
		return "", APIKey{}, err
	}
	token = "ick_" + hex.EncodeToString(buf)
	prefix := token[:12]
	sum := sha256.Sum256([]byte(token))
	hash := hex.EncodeToString(sum[:])
	now := time.Now().UnixMilli()

	res, err := s.db.Exec(
		`INSERT INTO api_keys (label, prefix, hash, created) VALUES (?,?,?,?)`,
		label, prefix, hash, now)
	if err != nil {
		return "", APIKey{}, err
	}
	id, _ := res.LastInsertId()
	return token, APIKey{ID: id, Label: label, Prefix: prefix, Created: now}, nil
}

// ListAPIKeys returns all key metadata (never the token or hash), newest first.
func (s *Store) ListAPIKeys() ([]APIKey, error) {
	rows, err := s.db.Query(`SELECT id, label, prefix, created FROM api_keys ORDER BY id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []APIKey
	for rows.Next() {
		var k APIKey
		if err := rows.Scan(&k.ID, &k.Label, &k.Prefix, &k.Created); err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

// DeleteAPIKey revokes a key by id.
func (s *Store) DeleteAPIKey(id int64) error {
	_, err := s.db.Exec(`DELETE FROM api_keys WHERE id = ?`, id)
	return err
}

// HasAPIKeys reports whether any control-API key exists. Auth is opt-in: while
// this is false the MCP endpoint stays open (loopback trust); once the operator
// creates a key, a valid bearer token is required.
func (s *Store) HasAPIKeys() (bool, error) {
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(1) FROM api_keys`).Scan(&n); err != nil {
		return false, err
	}
	return n > 0, nil
}

// VerifyAPIKey reports whether token matches a stored key (constant work via the
// hash index). Intended for gating remote control-API access.
func (s *Store) VerifyAPIKey(token string) (bool, error) {
	sum := sha256.Sum256([]byte(token))
	var n int
	err := s.db.QueryRow(`SELECT COUNT(1) FROM api_keys WHERE hash = ?`, hex.EncodeToString(sum[:])).Scan(&n)
	if err != nil {
		return false, err
	}
	return n > 0, nil
}
