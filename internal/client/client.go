// Package client talks to the SysRail daemon over a Unix socket or TCP.
package client

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/w512/SysRail/internal/core"
)

// Client is an API client.
type Client struct {
	http    *http.Client
	base    string
	token   string
	headers map[string]string
}

// New returns a client for target, which is either an http(s):// URL, a
// unix:// URL, or a filesystem path to a Unix socket. token may be empty.
func New(target, token string) (*Client, error) {
	c := &Client{token: token, headers: map[string]string{}}
	switch {
	case strings.HasPrefix(target, "http://"), strings.HasPrefix(target, "https://"):
		u, err := url.Parse(target)
		if err != nil {
			return nil, fmt.Errorf("parse daemon URL: %w", err)
		}
		c.base = strings.TrimSuffix(u.String(), "/")
		c.http = &http.Client{}
	default:
		path := strings.TrimPrefix(target, "unix://")
		if path == "" {
			return nil, fmt.Errorf("empty daemon address")
		}
		c.base = "http://sysrail"
		c.http = &http.Client{Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", path)
			},
		}}
	}
	return c, nil
}

// SetHeader adds a header to every request.
func (c *Client) SetHeader(name, value string) { c.headers[name] = value }

// Do sends a request and decodes the JSON response into out (if non-nil).
// API errors are returned as *core.Error; the HTTP status is returned too.
func (c *Client) Do(ctx context.Context, method, path string, body, out any) (int, error) {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return 0, err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, rd)
	if err != nil {
		return 0, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	for k, v := range c.headers {
		req.Header.Set(k, v)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return 0, &core.Error{Code: core.CodeProviderUnavailable, Message: "cannot reach sysrail daemon: " + err.Error(), Retryable: true}
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if err != nil {
		return resp.StatusCode, err
	}
	if resp.StatusCode >= 400 {
		var eb struct {
			Error *core.Error `json:"error"`
		}
		if json.Unmarshal(raw, &eb) == nil && eb.Error != nil {
			return resp.StatusCode, eb.Error
		}
		return resp.StatusCode, core.Errorf(core.CodeExecutionFailed, "daemon returned HTTP %d", resp.StatusCode)
	}
	if out != nil && len(raw) > 0 {
		if err := json.Unmarshal(raw, out); err != nil {
			return resp.StatusCode, fmt.Errorf("decode response: %w", err)
		}
	}
	return resp.StatusCode, nil
}

// Wait polls the health endpoint until the daemon answers or timeout passes.
func (c *Client) Wait(ctx context.Context, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		_, err := c.Do(ctx, http.MethodGet, "/v1/health", nil, nil)
		if err == nil || time.Now().After(deadline) {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
}
