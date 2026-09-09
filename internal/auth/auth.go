// Package auth issues and verifies bearer tokens. Only SHA-256 hashes of
// tokens are ever stored.
package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"regexp"
	"sort"
)

// TokenPrefix makes tokens recognizable to secret scanners and redaction.
const TokenPrefix = "sysrail_"

var hashPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

// NewToken returns a random token and its hash.
func NewToken() (token, hash string, err error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", "", fmt.Errorf("generate token: %w", err)
	}
	token = TokenPrefix + base64.RawURLEncoding.EncodeToString(b[:])
	return token, Hash(token), nil
}

// Hash returns the hex SHA-256 of token.
func Hash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// ValidHash reports whether h looks like a hex SHA-256 digest.
func ValidHash(h string) bool { return hashPattern.MatchString(h) }

// Authenticator maps tokens to agent names.
type Authenticator struct {
	names  []string
	hashes [][]byte
}

// NewAuthenticator builds an authenticator from agent name -> token hash.
func NewAuthenticator(agentHashes map[string]string) (*Authenticator, error) {
	a := &Authenticator{}
	names := make([]string, 0, len(agentHashes))
	for n := range agentHashes {
		names = append(names, n)
	}
	sort.Strings(names)
	seen := map[string]string{}
	for _, n := range names {
		h := agentHashes[n]
		if !ValidHash(h) {
			return nil, fmt.Errorf("agent %q: token_sha256 must be 64 lowercase hex characters", n)
		}
		if other, dup := seen[h]; dup {
			return nil, fmt.Errorf("agents %q and %q share a token", other, n)
		}
		seen[h] = n
		raw, _ := hex.DecodeString(h)
		a.names = append(a.names, n)
		a.hashes = append(a.hashes, raw)
	}
	return a, nil
}

// Agent returns the agent owning token. Every configured hash is compared in
// constant time.
func (a *Authenticator) Agent(token string) (string, bool) {
	if token == "" {
		return "", false
	}
	sum := sha256.Sum256([]byte(token))
	found := -1
	for i, h := range a.hashes {
		if subtle.ConstantTimeCompare(sum[:], h) == 1 {
			found = i
		}
	}
	if found < 0 {
		return "", false
	}
	return a.names[found], true
}
