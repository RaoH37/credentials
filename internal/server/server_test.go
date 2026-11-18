package server

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/RaoH37/credentials/internal/store"
	"github.com/RaoH37/credentials/internal/vault"
)

func newTestHandler(t *testing.T) (http.Handler, *store.Store) {
	t.Helper()
	st, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "test.db"),
		[]byte("test passphrase"),
		store.WithKDFParams(vault.KDFParams{Time: 1, Memory: 8 * 1024, Threads: 1}))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return New(st, slog.New(slog.NewTextHandler(io.Discard, nil))), st
}

func do(t *testing.T, h http.Handler, method, target, body string, headers ...string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, "http://localhost:12345"+target, strings.NewReader(body))
	for i := 0; i+1 < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestAPILifecycle(t *testing.T) {
	h, _ := newTestHandler(t)

	rec := do(t, h, "POST", "/credentials",
		`{"name":"MyWebService","description":"a description","format":"json","credentials":"{\"user\":\"bob\"}"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", rec.Code, rec.Body)
	}
	var created store.Credential
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	if loc := rec.Header().Get("Location"); loc != "/credentials/1" {
		t.Errorf("Location = %q", loc)
	}

	rec = do(t, h, "GET", "/credentials/1", "")
	var got map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if rec.Code != http.StatusOK || got["credentials"] != `{"user":"bob"}` || got["name"] != "MyWebService" || got["id"] != float64(1) {
		t.Fatalf("get: %d %v", rec.Code, got)
	}

	rec = do(t, h, "GET", "/credentials/1/raw", "")
	if rec.Body.String() != `{"user":"bob"}` || rec.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("raw: %q %q", rec.Body, rec.Header().Get("Content-Type"))
	}
	rec = do(t, h, "GET", "/by-name/MyWebService/raw", "")
	if rec.Body.String() != `{"user":"bob"}` {
		t.Fatalf("raw by name: %q", rec.Body)
	}

	rec = do(t, h, "GET", "/credentials", "")
	if rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), "bob") {
		t.Fatalf("list must not expose content: %d %s", rec.Code, rec.Body)
	}

	rec = do(t, h, "PUT", "/credentials/1", `{"name":"MyWebService","format":"txt","credentials":"new"}`)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"new"`) {
		t.Fatalf("update: %d %s", rec.Code, rec.Body)
	}

	if rec = do(t, h, "DELETE", "/credentials/1", ""); rec.Code != http.StatusNoContent {
		t.Fatalf("delete: %d", rec.Code)
	}
	if rec = do(t, h, "GET", "/credentials/1", ""); rec.Code != http.StatusNotFound {
		t.Fatalf("get after delete: %d", rec.Code)
	}
}

func TestAPIErrors(t *testing.T) {
	h, _ := newTestHandler(t)
	tests := []struct {
		name, method, target, body string
		want                       int
	}{
		{"invalid id", "GET", "/credentials/abc", "", http.StatusBadRequest},
		{"negative id", "GET", "/credentials/-1", "", http.StatusBadRequest},
		{"not found", "GET", "/credentials/42", "", http.StatusNotFound},
		{"unknown name", "GET", "/by-name/nope", "", http.StatusNotFound},
		{"invalid json", "POST", "/credentials", "{", http.StatusBadRequest},
		{"unknown field", "POST", "/credentials", `{"name":"a","id":5}`, http.StatusBadRequest},
		{"trailing data", "POST", "/credentials", `{"name":"a"} {}`, http.StatusBadRequest},
		{"invalid format", "POST", "/credentials", `{"name":"a","format":"json","credentials":"{"}`, http.StatusBadRequest},
		{"missing name", "POST", "/credentials", `{"credentials":"x"}`, http.StatusBadRequest},
		{"too large", "POST", "/credentials", `{"name":"a","credentials":"` + strings.Repeat("a", maxBodySize) + `"}`, http.StatusRequestEntityTooLarge},
		{"wrong method", "PATCH", "/credentials/1", "", http.StatusMethodNotAllowed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := do(t, h, tt.method, tt.target, tt.body)
			if rec.Code != tt.want {
				t.Fatalf("got %d, want %d: %s", rec.Code, tt.want, rec.Body)
			}
		})
	}

	rec := do(t, h, "POST", "/credentials", `{"name":"a"}`, "Content-Type", "text/plain")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("wrong content type: %d", rec.Code)
	}
}

func TestRejectsNonLocalHost(t *testing.T) {
	h, _ := newTestHandler(t)
	for host, want := range map[string]int{
		"localhost:12345":  http.StatusOK,
		"LOCALHOST":        http.StatusOK,
		"127.0.0.1:12345":  http.StatusOK,
		"[::1]:12345":      http.StatusOK,
		"evil.com":         http.StatusForbidden,
		"evil.com:12345":   http.StatusForbidden,
		"localhost.evil":   http.StatusForbidden,
		"192.168.1.10:123": http.StatusForbidden,
	} {
		req := httptest.NewRequest("GET", "/credentials", nil)
		req.Host = host
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != want {
			t.Errorf("Host %q: got %d, want %d", host, rec.Code, want)
		}
	}
}

func TestRejectsCrossOriginWrites(t *testing.T) {
	h, st := newTestHandler(t)
	if err := st.Create(context.Background(), &store.Credential{Name: "keep", Content: "x"}); err != nil {
		t.Fatal(err)
	}
	rec := do(t, h, "POST", "/admin/1/delete", "",
		"Sec-Fetch-Site", "cross-site", "Origin", "https://evil.example")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("cross-site delete: got %d, want 403", rec.Code)
	}
	if _, err := st.Get(context.Background(), 1); err != nil {
		t.Fatalf("credential was deleted: %v", err)
	}
	// Same-origin browser requests are allowed.
	rec = do(t, h, "POST", "/admin/1/delete", "", "Sec-Fetch-Site", "same-origin")
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("same-origin delete: got %d", rec.Code)
	}
}

func TestSecurityHeaders(t *testing.T) {
	h, _ := newTestHandler(t)
	for _, target := range []string{"/admin", "/credentials"} {
		rec := do(t, h, "GET", target, "")
		for k, v := range map[string]string{
			"Cache-Control":          "no-store",
			"X-Content-Type-Options": "nosniff",
			"X-Frame-Options":        "DENY",
		} {
			if got := rec.Header().Get(k); got != v {
				t.Errorf("%s: %s = %q, want %q", target, k, got, v)
			}
		}
		if !strings.Contains(rec.Header().Get("Content-Security-Policy"), "default-src 'none'") {
			t.Errorf("%s: missing CSP", target)
		}
	}
}

func TestAdminForms(t *testing.T) {
	h, st := newTestHandler(t)
	ctx := context.Background()
	form := url.Values{
		"name":        {"FormSvc"},
		"description": {"<script>alert(1)</script>"},
		"format":      {"yaml"},
		"credentials": {"user: bob\r\npass: x\r\n"},
	}
	ct := []string{"Content-Type", "application/x-www-form-urlencoded"}

	rec := do(t, h, "POST", "/admin/new", form.Encode(), ct...)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("create: %d %s", rec.Code, rec.Body)
	}
	c, err := st.GetByName(ctx, "FormSvc")
	if err != nil {
		t.Fatal(err)
	}
	if c.Content != "user: bob\npass: x\n" {
		t.Errorf("CRLF not normalized: %q", c.Content)
	}

	rec = do(t, h, "GET", "/admin", "")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "FormSvc") {
		t.Fatalf("list: %d", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "<script>alert(1)</script>") {
		t.Error("description is not HTML-escaped")
	}

	rec = do(t, h, "GET", "/admin/1", "")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "user: bob") {
		t.Fatalf("edit page: %d", rec.Code)
	}

	form.Set("format", "json") // content is not valid JSON
	rec = do(t, h, "POST", "/admin/1", form.Encode(), ct...)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "invalid JSON") {
		t.Fatalf("invalid update: %d", rec.Code)
	}

	if rec = do(t, h, "GET", "/admin/99", ""); rec.Code != http.StatusNotFound {
		t.Fatalf("missing credential page: %d", rec.Code)
	}
}
