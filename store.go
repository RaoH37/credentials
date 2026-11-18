package main

import (
	"crypto/rand"
	"database/sql"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	_ "modernc.org/sqlite" // driver SQLite en pur Go, sans CGO
)

var ErrNotFound = errors.New("credential introuvable")

type Credential struct {
	ID          int64     `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Format      string    `json:"format"`
	Credentials string    `json:"credentials,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type Store struct {
	db     *sql.DB
	cipher *Cipher
}

const schema = `
CREATE TABLE IF NOT EXISTS meta (
	key   TEXT PRIMARY KEY,
	value BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS credentials (
	id          INTEGER PRIMARY KEY AUTOINCREMENT,
	name        TEXT NOT NULL UNIQUE,
	description TEXT NOT NULL DEFAULT '',
	format      TEXT NOT NULL DEFAULT 'txt',
	credentials BLOB NOT NULL,
	created_at  INTEGER NOT NULL,
	updated_at  INTEGER NOT NULL
);`

// OpenStore ouvre (ou crée) la base et dérive la clé depuis la passphrase.
// À la première ouverture, un sel et un vérificateur sont générés et stockés.
func OpenStore(path, passphrase string) (*Store, error) {
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("création du schéma : %w", err)
	}

	var salt, verifier []byte
	err = db.QueryRow(`SELECT value FROM meta WHERE key='salt'`).Scan(&salt)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		// Nouvelle base : initialisation.
		salt = make([]byte, saltLen)
		if _, err := rand.Read(salt); err != nil {
			db.Close()
			return nil, err
		}
		c, err := NewCipher(deriveKey(passphrase, salt))
		if err != nil {
			db.Close()
			return nil, err
		}
		verifier, err = c.Encrypt([]byte(verifierPlaintext), []byte("verifier"))
		if err != nil {
			db.Close()
			return nil, err
		}
		if _, err := db.Exec(`INSERT INTO meta(key,value) VALUES ('salt',?),('verifier',?)`, salt, verifier); err != nil {
			db.Close()
			return nil, err
		}
		return &Store{db: db, cipher: c}, nil
	case err != nil:
		db.Close()
		return nil, err
	}

	if err := db.QueryRow(`SELECT value FROM meta WHERE key='verifier'`).Scan(&verifier); err != nil {
		db.Close()
		return nil, fmt.Errorf("lecture du vérificateur : %w", err)
	}
	c, err := NewCipher(deriveKey(passphrase, salt))
	if err != nil {
		db.Close()
		return nil, err
	}
	if pt, err := c.Decrypt(verifier, []byte("verifier")); err != nil || string(pt) != verifierPlaintext {
		db.Close()
		return nil, ErrBadPassphrase
	}
	return &Store{db: db, cipher: c}, nil
}

func (s *Store) Close() error { return s.db.Close() }

func aadFor(id int64) []byte { return []byte("credential:" + strconv.FormatInt(id, 10)) }

func (s *Store) List() ([]Credential, error) {
	rows, err := s.db.Query(`SELECT id,name,description,format,created_at,updated_at FROM credentials ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Credential
	for rows.Next() {
		var c Credential
		var ca, ua int64
		if err := rows.Scan(&c.ID, &c.Name, &c.Description, &c.Format, &ca, &ua); err != nil {
			return nil, err
		}
		c.CreatedAt, c.UpdatedAt = time.Unix(ca, 0), time.Unix(ua, 0)
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *Store) get(where string, arg any) (*Credential, error) {
	var c Credential
	var blob []byte
	var ca, ua int64
	err := s.db.QueryRow(`SELECT id,name,description,format,credentials,created_at,updated_at FROM credentials WHERE `+where, arg).
		Scan(&c.ID, &c.Name, &c.Description, &c.Format, &blob, &ca, &ua)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	pt, err := s.cipher.Decrypt(blob, aadFor(c.ID))
	if err != nil {
		return nil, fmt.Errorf("déchiffrement du credential %d : %w", c.ID, err)
	}
	c.Credentials = string(pt)
	c.CreatedAt, c.UpdatedAt = time.Unix(ca, 0), time.Unix(ua, 0)
	return &c, nil
}

func (s *Store) Get(id int64) (*Credential, error)          { return s.get("id = ?", id) }
func (s *Store) GetByName(name string) (*Credential, error) { return s.get("name = ?", name) }

// Create insère la ligne puis écrit le chiffré, dans une transaction, car l'AAD
// dépend de l'id attribué par SQLite.
func (s *Store) Create(c *Credential) error {
	if err := normalize(c); err != nil {
		return err
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	now := time.Now().Truncate(time.Second)
	res, err := tx.Exec(`INSERT INTO credentials(name,description,format,credentials,created_at,updated_at) VALUES (?,?,?,x'',?,?)`,
		c.Name, c.Description, c.Format, now.Unix(), now.Unix())
	if err != nil {
		return wrapUnique(err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return err
	}
	blob, err := s.cipher.Encrypt([]byte(c.Credentials), aadFor(id))
	if err != nil {
		return err
	}
	if _, err := tx.Exec(`UPDATE credentials SET credentials=? WHERE id=?`, blob, id); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	c.ID, c.CreatedAt, c.UpdatedAt = id, now, now
	return nil
}

func (s *Store) Update(c *Credential) error {
	if err := normalize(c); err != nil {
		return err
	}
	blob, err := s.cipher.Encrypt([]byte(c.Credentials), aadFor(c.ID))
	if err != nil {
		return err
	}
	res, err := s.db.Exec(`UPDATE credentials SET name=?,description=?,format=?,credentials=?,updated_at=? WHERE id=?`,
		c.Name, c.Description, c.Format, blob, time.Now().Unix(), c.ID)
	if err != nil {
		return wrapUnique(err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

func (s *Store) Delete(id int64) error {
	res, err := s.db.Exec(`DELETE FROM credentials WHERE id=?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

type ValidationError struct{ Msg string }

func (e *ValidationError) Error() string { return e.Msg }

func normalize(c *Credential) error {
	c.Name = strings.TrimSpace(c.Name)
	c.Description = strings.TrimSpace(c.Description)
	c.Format = strings.ToLower(strings.TrimSpace(c.Format))
	if c.Format == "" {
		c.Format = "txt"
	}
	if c.Name == "" {
		return &ValidationError{"le nom est obligatoire"}
	}
	if err := ValidateFormat(c.Format, c.Credentials); err != nil {
		return &ValidationError{err.Error()}
	}
	return nil
}

func wrapUnique(err error) error {
	if strings.Contains(err.Error(), "UNIQUE constraint failed") {
		return &ValidationError{"un credential porte déjà ce nom"}
	}
	return err
}
