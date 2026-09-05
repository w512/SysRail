// Package redact masks secrets in values before they are returned to agents
// or persisted (spec §17, §30). It is best-effort: it recognizes common secret
// shapes, not every possible secret.
package redact

import (
	"encoding/json"
	"regexp"
)

// Mask replaces redacted content.
const Mask = "[REDACTED]"

const keyWords = `pass(?:word|wd|phrase)?|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|` +
	`(?:ssh|gpg|signing|encryption)[_-]?key|credentials?|authorization|cookie|session[_-]?(?:id|key|token)|dsn`

var (
	sensitiveKey = regexp.MustCompile(`(?i)(?:` + keyWords + `)`)

	pemBlock = regexp.MustCompile(`-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----(?s:.*?)(?:-----END [A-Z0-9 ]*PRIVATE KEY-----|$)`)
	jwt      = regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}`)
	authHdr  = regexp.MustCompile(`(?i)\b(bearer|basic|token)(\s+)[A-Za-z0-9._~+/=-]{8,}`)
	urlCreds = regexp.MustCompile(`(?i)\b([a-z][a-z0-9+.-]*://[^/\s:@]+:)[^/\s@]+@`)
	// KEY=value, KEY: value, "key": "value" where the key looks sensitive.
	keyValue = regexp.MustCompile(`(?i)("?[A-Za-z0-9_.-]*(?:` + keyWords + `)[A-Za-z0-9_.-]*"?)(\s*[=:]\s*)("[^"]*"|'[^']*'|[^\s,;&"']+)`)
	tokens   = regexp.MustCompile(`\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{20,}|AKIA[0-9A-Z]{16}|` +
		`xox[abprs]-[A-Za-z0-9-]{10,}|sk-[A-Za-z0-9_-]{20,}|AIza[0-9A-Za-z_-]{35}|glpat-[A-Za-z0-9_-]{20,})`)
)

// IsSensitiveKey reports whether a field name suggests a secret value.
func IsSensitiveKey(key string) bool { return sensitiveKey.MatchString(key) }

// String masks secrets embedded in free-form text such as log lines.
func String(s string) string {
	if s == "" {
		return s
	}
	s = pemBlock.ReplaceAllString(s, Mask)
	s = jwt.ReplaceAllString(s, Mask)
	s = tokens.ReplaceAllString(s, Mask)
	s = urlCreds.ReplaceAllString(s, "${1}"+Mask+"@")
	s = authHdr.ReplaceAllString(s, "${1}${2}"+Mask)
	s = keyValue.ReplaceAllStringFunc(s, func(m string) string {
		parts := keyValue.FindStringSubmatch(m)
		value := parts[3]
		if value == Mask || value == `"`+Mask+`"` {
			return m
		}
		if len(value) > 0 && (value[0] == '"' || value[0] == '\'') {
			return parts[1] + parts[2] + value[:1] + Mask + value[:1]
		}
		return parts[1] + parts[2] + Mask
	})
	return s
}

// Value returns a copy of a JSON-like value (as produced by encoding/json)
// with sensitive fields and embedded secrets masked.
func Value(v any) any {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, val := range t {
			if IsSensitiveKey(k) && val != nil && val != "" {
				out[k] = Mask
				continue
			}
			out[k] = Value(val)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, val := range t {
			out[i] = Value(val)
		}
		return out
	case string:
		return String(t)
	}
	return v
}

// JSON redacts a JSON document. Invalid JSON is treated as text.
func JSON(raw json.RawMessage) json.RawMessage {
	if len(raw) == 0 {
		return raw
	}
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		b, _ := json.Marshal(String(string(raw)))
		return b
	}
	b, err := json.Marshal(Value(v))
	if err != nil {
		return json.RawMessage(`"` + Mask + `"`)
	}
	return b
}

// Marshal encodes v as JSON and redacts the result.
func Marshal(v any) (json.RawMessage, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return JSON(b), nil
}
