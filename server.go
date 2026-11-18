package main

import (
	"embed"
	"encoding/json"
	"errors"
	"html/template"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
)

//go:embed templates/*.html
var templateFS embed.FS

type Server struct {
	store *Store
	tmpl  *template.Template
}

func NewServer(store *Store) *Server {
	tmpl := template.Must(template.ParseFS(templateFS, "templates/*.html"))
	return &Server{store: store, tmpl: tmpl}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	// API JSON
	mux.HandleFunc("GET /credentials", s.apiList)
	mux.HandleFunc("GET /credentials/{id}", s.apiGet)
	mux.HandleFunc("GET /credentials/{id}/raw", s.apiRaw)
	mux.HandleFunc("GET /by-name/{name}", s.apiGetByName)
	mux.HandleFunc("GET /by-name/{name}/raw", s.apiRawByName)
	mux.HandleFunc("POST /credentials", s.apiCreate)
	mux.HandleFunc("PUT /credentials/{id}", s.apiUpdate)
	mux.HandleFunc("DELETE /credentials/{id}", s.apiDelete)

	// Interface d'administration
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/admin", http.StatusFound)
	})
	mux.HandleFunc("GET /admin", s.adminList)
	mux.HandleFunc("GET /admin/new", s.adminNew)
	mux.HandleFunc("POST /admin/new", s.adminCreate)
	mux.HandleFunc("GET /admin/{id}", s.adminEdit)
	mux.HandleFunc("POST /admin/{id}", s.adminUpdate)
	mux.HandleFunc("POST /admin/{id}/delete", s.adminDelete)

	// Protection CSRF (requêtes cross-origin venant d'un navigateur) puis
	// protection contre le DNS rebinding (Host doit être local).
	return localHostOnly(http.NewCrossOriginProtection().Handler(logRequests(mux)))
}

// localHostOnly refuse les requêtes dont l'en-tête Host n'est pas une adresse
// locale : empêche un site malveillant d'atteindre l'API via DNS rebinding.
func localHostOnly(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.Host
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		host = strings.Trim(host, "[]")
		if host != "localhost" {
			if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
				http.Error(w, "host non autorisé", http.StatusForbidden)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		log.Printf("%s %s", r.Method, r.URL.Path)
		next.ServeHTTP(w, r)
	})
}

// ---------- API ----------

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

func writeErr(w http.ResponseWriter, err error) {
	var ve *ValidationError
	switch {
	case errors.Is(err, ErrNotFound):
		writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
	case errors.As(err, &ve):
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": ve.Msg})
	default:
		log.Printf("erreur : %v", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "erreur interne"})
	}
}

func pathID(r *http.Request) (int64, error) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		return 0, &ValidationError{"id invalide"}
	}
	return id, nil
}

func (s *Server) apiList(w http.ResponseWriter, r *http.Request) {
	list, err := s.store.List()
	if err != nil {
		writeErr(w, err)
		return
	}
	if list == nil {
		list = []Credential{}
	}
	writeJSON(w, http.StatusOK, list)
}

func (s *Server) lookup(r *http.Request) (*Credential, error) {
	if name := r.PathValue("name"); name != "" {
		return s.store.GetByName(name)
	}
	id, err := pathID(r)
	if err != nil {
		return nil, err
	}
	return s.store.Get(id)
}

func (s *Server) apiGet(w http.ResponseWriter, r *http.Request) {
	c, err := s.lookup(r)
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, c)
}

func (s *Server) apiGetByName(w http.ResponseWriter, r *http.Request) { s.apiGet(w, r) }

// apiRaw renvoie uniquement le contenu du credential, tel quel, avec le
// Content-Type correspondant à son format. Pratique pour :
//
//	curl -s localhost:12345/credentials/1/raw > config.yaml
func (s *Server) apiRaw(w http.ResponseWriter, r *http.Request) {
	c, err := s.lookup(r)
	if err != nil {
		writeErr(w, err)
		return
	}
	w.Header().Set("Content-Type", formats[c.Format])
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write([]byte(c.Credentials))
}

func (s *Server) apiRawByName(w http.ResponseWriter, r *http.Request) { s.apiRaw(w, r) }

func decodeBody(r *http.Request, c *Credential) error {
	dec := json.NewDecoder(http.MaxBytesReader(nil, r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(c); err != nil {
		return &ValidationError{"JSON invalide : " + err.Error()}
	}
	return nil
}

func (s *Server) apiCreate(w http.ResponseWriter, r *http.Request) {
	var c Credential
	if err := decodeBody(r, &c); err != nil {
		writeErr(w, err)
		return
	}
	if err := s.store.Create(&c); err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, c)
}

func (s *Server) apiUpdate(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		writeErr(w, err)
		return
	}
	var c Credential
	if err := decodeBody(r, &c); err != nil {
		writeErr(w, err)
		return
	}
	c.ID = id
	if err := s.store.Update(&c); err != nil {
		writeErr(w, err)
		return
	}
	updated, err := s.store.Get(id)
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, http.StatusOK, updated)
}

func (s *Server) apiDelete(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		writeErr(w, err)
		return
	}
	if err := s.store.Delete(id); err != nil {
		writeErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ---------- Administration ----------

type pageData struct {
	Title   string
	List    []Credential
	Cred    *Credential
	Formats []string
	Error   string
	Flash   string
	IsNew   bool
}

func (s *Server) render(w http.ResponseWriter, status int, name string, d pageData) {
	d.Formats = formatOrder
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Frame-Options", "DENY")
	w.WriteHeader(status)
	if err := s.tmpl.ExecuteTemplate(w, name, d); err != nil {
		log.Printf("template %s : %v", name, err)
	}
}

func (s *Server) adminList(w http.ResponseWriter, r *http.Request) {
	list, err := s.store.List()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	flash := map[string]string{
		"created": "Credential créé.",
		"updated": "Credential mis à jour.",
		"deleted": "Credential supprimé.",
	}[r.URL.Query().Get("ok")]
	s.render(w, http.StatusOK, "list.html", pageData{Title: "Credentials", List: list, Flash: flash})
}

func (s *Server) adminNew(w http.ResponseWriter, r *http.Request) {
	s.render(w, http.StatusOK, "edit.html", pageData{Title: "Nouveau credential", Cred: &Credential{Format: "json"}, IsNew: true})
}

func credFromForm(r *http.Request) *Credential {
	return &Credential{
		Name:        r.FormValue("name"),
		Description: r.FormValue("description"),
		Format:      r.FormValue("format"),
		Credentials: strings.ReplaceAll(r.FormValue("credentials"), "\r\n", "\n"),
	}
}

func (s *Server) adminCreate(w http.ResponseWriter, r *http.Request) {
	c := credFromForm(r)
	if err := s.store.Create(c); err != nil {
		s.formError(w, c, true, err)
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
	c, err := s.store.Get(id)
	if errors.Is(err, ErrNotFound) {
		http.NotFound(w, r)
		return
	} else if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.render(w, http.StatusOK, "edit.html", pageData{Title: c.Name, Cred: c})
}

func (s *Server) adminUpdate(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	c := credFromForm(r)
	c.ID = id
	if err := s.store.Update(c); err != nil {
		s.formError(w, c, false, err)
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
	if err := s.store.Delete(id); err != nil && !errors.Is(err, ErrNotFound) {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/admin?ok=deleted", http.StatusSeeOther)
}

func (s *Server) formError(w http.ResponseWriter, c *Credential, isNew bool, err error) {
	var ve *ValidationError
	if !errors.As(err, &ve) {
		log.Printf("erreur : %v", err)
		http.Error(w, "erreur interne", http.StatusInternalServerError)
		return
	}
	title := "Nouveau credential"
	if !isNew {
		title = c.Name
	}
	s.render(w, http.StatusBadRequest, "edit.html", pageData{Title: title, Cred: c, IsNew: isNew, Error: ve.Msg})
}
