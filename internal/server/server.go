// Package server exposes the credential store over HTTP: a JSON API and a
// server-rendered administration interface.
package server

import (
	"bytes"
	"embed"
	"encoding/json"
	"errors"
	"html/template"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/RaoH37/credentials/internal/store"
)

//go:embed templates/*.html
var templateFS embed.FS

var templates = template.Must(template.ParseFS(templateFS, "templates/*.html"))

// maxBodySize bounds request bodies: the largest credential plus room for
// the other fields and encoding overhead (form URL-encoding can triple size).
const maxBodySize = 3*store.MaxContentSize + 64<<10

// Server serves the API and the admin interface.
type Server struct {
	store  *store.Store
	logger *slog.Logger
}

// New returns the HTTP handler for st, with all security middleware applied.
func New(st *store.Store, logger *slog.Logger) http.Handler {
	s := &Server{store: st, logger: logger}

	mux := http.NewServeMux()

	// JSON API
	mux.HandleFunc("GET /credentials", s.apiList)
	mux.HandleFunc("GET /credentials/{id}", s.apiGet)
	mux.HandleFunc("GET /credentials/{id}/raw", s.apiRaw)
	mux.HandleFunc("GET /by-name/{name}", s.apiGet)
	mux.HandleFunc("GET /by-name/{name}/raw", s.apiRaw)
	mux.HandleFunc("POST /credentials", s.apiCreate)
	mux.HandleFunc("PUT /credentials/{id}", s.apiUpdate)
	mux.HandleFunc("DELETE /credentials/{id}", s.apiDelete)

	// Admin interface
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/admin", http.StatusFound)
	})
	mux.HandleFunc("GET /admin", s.adminList)
	mux.HandleFunc("GET /admin/new", s.adminNew)
	mux.HandleFunc("POST /admin/new", s.adminCreate)
	mux.HandleFunc("GET /admin/{id}", s.adminEdit)
	mux.HandleFunc("POST /admin/{id}", s.adminUpdate)
	mux.HandleFunc("POST /admin/{id}/delete", s.adminDelete)

	// Outermost first: reject non-local Host headers (DNS rebinding), then
	// cross-origin browser requests (CSRF), then set headers and log.
	var h http.Handler = mux
	h = securityHeaders(h)
	h = s.logRequests(h)
	h = http.NewCrossOriginProtection().Handler(h)
	h = localHostOnly(h)
	return h
}

// localHostOnly rejects requests whose Host header is not a loopback name or
// address, which defeats DNS rebinding attacks from malicious web pages.
func localHostOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !isLoopbackHost(r.Host) {
			http.Error(w, "forbidden host", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func isLoopbackHost(hostport string) bool {
	host := hostport
	if h, _, err := net.SplitHostPort(hostport); err == nil {
		host = h
	}
	host = strings.TrimSuffix(strings.Trim(host, "[]"), ".")
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// securityHeaders sets defensive headers on every response. Responses
// contain secrets: they must never be cached, framed or sniffed.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Cache-Control", "no-store")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		h.Set("Content-Security-Policy",
			"default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
		next.ServeHTTP(w, r)
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

func (s *Server) logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		// Never log query strings or bodies: they may contain secrets.
		s.logger.Info("request",
			"method", r.Method,
			"path", r.URL.Path,
			"status", rec.status,
			"duration", time.Since(start).Round(time.Microsecond))
	})
}

// ---------- API ----------

// credentialInput is the API request body. A dedicated type prevents
// clients from setting server-managed fields such as id or timestamps.
type credentialInput struct {
	Name        string       `json:"name"`
	Description string       `json:"description"`
	Format      store.Format `json:"format"`
	Credentials string       `json:"credentials"`
}

func (in credentialInput) toCredential(id int64) *store.Credential {
	return &store.Credential{
		ID:          id,
		Name:        in.Name,
		Description: in.Description,
		Format:      in.Format,
		Content:     in.Credentials,
	}
}

type errorResponse struct {
	Error string `json:"error"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(buf.Bytes())
}

func (s *Server) writeError(w http.ResponseWriter, r *http.Request, err error) {
	var ve *store.ValidationError
	var mbe *http.MaxBytesError
	switch {
	case errors.Is(err, store.ErrNotFound):
		writeJSON(w, http.StatusNotFound, errorResponse{err.Error()})
	case errors.As(err, &ve):
		writeJSON(w, http.StatusBadRequest, errorResponse{ve.Error()})
	case errors.As(err, &mbe):
		writeJSON(w, http.StatusRequestEntityTooLarge, errorResponse{"request body too large"})
	default:
		s.logger.Error("request failed", "method", r.Method, "path", r.URL.Path, "err", err)
		writeJSON(w, http.StatusInternalServerError, errorResponse{"internal error"})
	}
}

func pathID(r *http.Request) (int64, error) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		return 0, &store.ValidationError{Field: "id", Msg: "must be a positive integer"}
	}
	return id, nil
}

// lookup finds the credential designated by the {id} or {name} path value.
func (s *Server) lookup(r *http.Request) (*store.Credential, error) {
	if name := r.PathValue("name"); name != "" {
		return s.store.GetByName(r.Context(), name)
	}
	id, err := pathID(r)
	if err != nil {
		return nil, err
	}
	return s.store.Get(r.Context(), id)
}

func (s *Server) apiList(w http.ResponseWriter, r *http.Request) {
	list, err := s.store.List(r.Context())
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, list)
}

func (s *Server) apiGet(w http.ResponseWriter, r *http.Request) {
	c, err := s.lookup(r)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, c)
}

// apiRaw serves only the credential content, with the Content-Type of its
// format, e.g. curl -s localhost:12345/credentials/1/raw > config.yaml
func (s *Server) apiRaw(w http.ResponseWriter, r *http.Request) {
	c, err := s.lookup(r)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	w.Header().Set("Content-Type", c.Format.ContentType())
	w.Header().Set("Content-Disposition", "inline")
	_, _ = io.WriteString(w, c.Content)
}

func decodeJSON(w http.ResponseWriter, r *http.Request, dst any) error {
	if ct := r.Header.Get("Content-Type"); ct != "" && !strings.HasPrefix(ct, "application/json") {
		return &store.ValidationError{Msg: "Content-Type must be application/json"}
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBodySize))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			return err
		}
		return &store.ValidationError{Msg: "invalid JSON body: " + err.Error()}
	}
	if dec.More() {
		return &store.ValidationError{Msg: "invalid JSON body: unexpected data after object"}
	}
	return nil
}

func (s *Server) apiCreate(w http.ResponseWriter, r *http.Request) {
	var in credentialInput
	if err := decodeJSON(w, r, &in); err != nil {
		s.writeError(w, r, err)
		return
	}
	c := in.toCredential(0)
	if err := s.store.Create(r.Context(), c); err != nil {
		s.writeError(w, r, err)
		return
	}
	w.Header().Set("Location", "/credentials/"+strconv.FormatInt(c.ID, 10))
	writeJSON(w, http.StatusCreated, c)
}

func (s *Server) apiUpdate(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	var in credentialInput
	if err := decodeJSON(w, r, &in); err != nil {
		s.writeError(w, r, err)
		return
	}
	if err := s.store.Update(r.Context(), in.toCredential(id)); err != nil {
		s.writeError(w, r, err)
		return
	}
	c, err := s.store.Get(r.Context(), id)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, c)
}

func (s *Server) apiDelete(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		s.writeError(w, r, err)
		return
	}
	if err := s.store.Delete(r.Context(), id); err != nil {
		s.writeError(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ---------- Admin interface ----------

type pageData struct {
	Title   string
	List    []store.Credential
	Cred    *store.Credential
	Formats []store.Format
	Error   string
	Flash   string
	IsNew   bool
}

var flashMessages = map[string]string{
	"created": "Credential created.",
	"updated": "Credential updated.",
	"deleted": "Credential deleted.",
}

// render executes the template into a buffer first, so that a template error
// never results in a half-written page.
func (s *Server) render(w http.ResponseWriter, r *http.Request, status int, name string, d pageData) {
	d.Formats = store.Formats
	var buf bytes.Buffer
	if err := templates.ExecuteTemplate(&buf, name, d); err != nil {
		s.logger.Error("render template", "template", name, "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = buf.WriteTo(w)
}

func (s *Server) adminError(w http.ResponseWriter, r *http.Request, err error) {
	var mbe *http.MaxBytesError
	switch {
	case errors.Is(err, store.ErrNotFound):
		http.NotFound(w, r)
	case errors.As(err, &mbe):
		http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
	default:
		var ve *store.ValidationError
		if errors.As(err, &ve) {
			http.Error(w, ve.Error(), http.StatusBadRequest)
			return
		}
		s.logger.Error("request failed", "method", r.Method, "path", r.URL.Path, "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
	}
}

func (s *Server) adminList(w http.ResponseWriter, r *http.Request) {
	list, err := s.store.List(r.Context())
	if err != nil {
		s.adminError(w, r, err)
		return
	}
	s.render(w, r, http.StatusOK, "list.html", pageData{
		Title: "Credentials",
		List:  list,
		Flash: flashMessages[r.URL.Query().Get("ok")],
	})
}

func (s *Server) adminNew(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, http.StatusOK, "edit.html", pageData{
		Title: "New credential",
		Cred:  &store.Credential{Format: store.FormatJSON},
		IsNew: true,
	})
}

func credentialFromForm(w http.ResponseWriter, r *http.Request) (*store.Credential, error) {
	r.Body = http.MaxBytesReader(w, r.Body, maxBodySize)
	if err := r.ParseForm(); err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			return nil, err
		}
		return nil, &store.ValidationError{Msg: "invalid form data"}
	}
	return &store.Credential{
		Name:        r.PostFormValue("name"),
		Description: r.PostFormValue("description"),
		Format:      store.Format(r.PostFormValue("format")),
		// Browsers submit textarea line breaks as CRLF.
		Content: strings.ReplaceAll(r.PostFormValue("credentials"), "\r\n", "\n"),
	}, nil
}

func (s *Server) adminCreate(w http.ResponseWriter, r *http.Request) {
	c, err := credentialFromForm(w, r)
	if err != nil {
		s.adminError(w, r, err)
		return
	}
	if err := s.store.Create(r.Context(), c); err != nil {
		s.formError(w, r, c, true, err)
		return
	}
	http.Redirect(w, r, "/admin?ok=created", http.StatusSeeOther)
}

func (s *Server) adminEdit(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	c, err := s.store.Get(r.Context(), id)
	if err != nil {
		s.adminError(w, r, err)
		return
	}
	s.render(w, r, http.StatusOK, "edit.html", pageData{Title: c.Name, Cred: c})
}

func (s *Server) adminUpdate(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	c, err := credentialFromForm(w, r)
	if err != nil {
		s.adminError(w, r, err)
		return
	}
	c.ID = id
	if err := s.store.Update(r.Context(), c); err != nil {
		s.formError(w, r, c, false, err)
		return
	}
	http.Redirect(w, r, "/admin?ok=updated", http.StatusSeeOther)
}

func (s *Server) adminDelete(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if err := s.store.Delete(r.Context(), id); err != nil && !errors.Is(err, store.ErrNotFound) {
		s.adminError(w, r, err)
		return
	}
	http.Redirect(w, r, "/admin?ok=deleted", http.StatusSeeOther)
}

// formError re-renders the form with the user's input and the validation
// message, or fails with a generic error for anything else.
func (s *Server) formError(w http.ResponseWriter, r *http.Request, c *store.Credential, isNew bool, err error) {
	var ve *store.ValidationError
	if !errors.As(err, &ve) {
		s.adminError(w, r, err)
		return
	}
	title := "New credential"
	if !isNew {
		title = c.Name
	}
	s.render(w, r, http.StatusBadRequest, "edit.html", pageData{Title: title, Cred: c, IsNew: isNew, Error: ve.Error()})
}
