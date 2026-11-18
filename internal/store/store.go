// Package store persists credentials in a SQLite database. The credential
// content is encrypted with AES-256-GCM using a key derived from a passphrase;
// names, descriptions and formats are stored in clear text.
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
	"unicode"
	"unicode/utf8"

	"modernc.org/sqlite" // pure-Go SQLite driver, no CGO
	sqlite3 "modernc.org/sqlite/lib"

	"github.com/RaoH37/credentials/internal/vault"
)

// Limits on credential fields.
const (
	MaxNameLen        = 128     // runes
	MaxDescriptionLen = 1024    // runes
	MaxContentSize    = 1 << 20 // bytes
)

// Sentinel errors.
var (
	ErrNotFound        = errors.New("credential not found")
	ErrWrongPassphrase = errors.New("wrong passphrase")
	ErrLocked          = errors.New("database is already in use by another process")
)

// ValidationError reports invalid user input. Its message is safe to show to
// the user.
type ValidationError struct {
	Field string
	Msg   string
}

func (e *ValidationError) Error() string {
	if e.Field == "" {
		return e.Msg
	}
	return e.Field + ": " + e.Msg
}

// Credential is a stored secret. Content is only populated by Get and
// GetByName.
type Credential struct {
	ID          int64     `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Format      Format    `json:"format"`
	Content     string    `json:"credentials,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// Store is a handle on an open, unlocked credentials database. It is safe for
// concurrent use.
type Store struct {
	db     *sql.DB
	lock   *os.File
	cipher atomic.Pointer[vault.Cipher] // swapped by Rekey
}

// The on-disk format (table layout, AAD strings, verifier) must stay
// compatible with existing databases.
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

const (
	verifierPlaintext = "credentials-vault-ok"
	verifierAAD       = "verifier"
	metaSalt          = "salt"
	metaVerifier      = "verifier"
	metaKDF           = "kdf"
)

// legacyKDFParams are the parameters used by databases created before the
// "kdf" meta key existed.
var legacyKDFParams = vault.DefaultKDFParams

type options struct {
	kdf vault.KDFParams
}

// Option configures Open.
type Option func(*options)

// WithKDFParams sets the Argon2id parameters used when a new database is
// created (or rekeyed). Existing databases keep the parameters they store.
func WithKDFParams(p vault.KDFParams) Option {
	return func(o *options) { o.kdf = p }
}

// Open opens the database at path, creating it if needed, and unlocks it with
// passphrase. It returns ErrWrongPassphrase if the passphrase does not match
// and ErrLocked if another process has the database open.
func Open(ctx context.Context, path string, passphrase []byte, opts ...Option) (_ *Store, err error) {
	o := options{kdf: vault.DefaultKDFParams}
	for _, opt := range opts {
		opt(&o)
	}
	if err := o.kdf.Validate(); err != nil {
		return nil, err
	}
	if len(passphrase) == 0 {
		return nil, errors.New("empty passphrase")
	}
	// The driver splits the DSN on '?': such a path would be misinterpreted.
	if strings.ContainsAny(path, "?#") {
		return nil, fmt.Errorf("database path must not contain '?' or '#': %q", path)
	}

	lock, err := lockFile(path + ".lock")
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			lock.Close()
		}
	}()

	dsn := path + "?_pragma=busy_timeout(5000)" +
		"&_pragma=journal_mode(WAL)" +
		"&_pragma=secure_delete(ON)" + // overwrite deleted content
		"&_pragma=foreign_keys(ON)" +
		"&_txlock=immediate"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}
	defer func() {
		if err != nil {
			db.Close()
		}
	}()
	// A single connection serializes access and guarantees the per-connection
	// pragmas above always apply.
	db.SetMaxOpenConns(1)
	db.SetConnMaxLifetime(0)

	if _, err := db.ExecContext(ctx, schema); err != nil {
		return nil, fmt.Errorf("create schema: %w", err)
	}
	restrictPermissions(path)

	s := &Store{db: db, lock: lock}
	if err := s.unlock(ctx, passphrase, o.kdf); err != nil {
		return nil, err
	}
	return s, nil
}

// restrictPermissions makes the database files readable by the owner only.
// The process umask should already guarantee it; this is defense in depth.
func restrictPermissions(path string) {
	for _, p := range []string{path, path + "-wal", path + "-shm"} {
		_ = os.Chmod(p, 0o600) // missing -wal/-shm files are fine
	}
}

func (s *Store) unlock(ctx context.Context, passphrase []byte, newKDF vault.KDFParams) error {
	meta, err := s.readMeta(ctx)
	if err != nil {
		return err
	}
	salt, ok := meta[metaSalt]
	if !ok {
		return s.initialize(ctx, passphrase, newKDF)
	}
	verifier, ok := meta[metaVerifier]
	if !ok {
		return errors.New("corrupted database: verifier missing")
	}
	kdf := legacyKDFParams
	if raw, ok := meta[metaKDF]; ok {
		if kdf, err = vault.ParseKDFParams(string(raw)); err != nil {
			return fmt.Errorf("corrupted database: %w", err)
		}
	}
	c, err := vault.NewCipher(vault.DeriveKey(passphrase, salt, kdf))
	if err != nil {
		return err
	}
	pt, err := c.Decrypt(verifier, []byte(verifierAAD))
	if err != nil || string(pt) != verifierPlaintext {
		return ErrWrongPassphrase
	}
	s.cipher.Store(c)
	return nil
}

func (s *Store) readMeta(ctx context.Context) (map[string][]byte, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT key, value FROM meta`)
	if err != nil {
		return nil, fmt.Errorf("read metadata: %w", err)
	}
	defer rows.Close()
	meta := make(map[string][]byte)
	for rows.Next() {
		var k string
		var v []byte
		if err := rows.Scan(&k, &v); err != nil {
			return nil, fmt.Errorf("read metadata: %w", err)
		}
		meta[k] = v
	}
	return meta, rows.Err()
}

// newKeyMaterial derives a fresh key (new salt) and the matching verifier.
func newKeyMaterial(passphrase []byte, kdf vault.KDFParams) (c *vault.Cipher, salt, verifier []byte, err error) {
	if salt, err = vault.NewSalt(); err != nil {
		return nil, nil, nil, err
	}
	if c, err = vault.NewCipher(vault.DeriveKey(passphrase, salt, kdf)); err != nil {
		return nil, nil, nil, err
	}
	if verifier, err = c.Encrypt([]byte(verifierPlaintext), []byte(verifierAAD)); err != nil {
		return nil, nil, nil, err
	}
	return c, salt, verifier, nil
}

func writeKeyMeta(ctx context.Context, tx *sql.Tx, salt, verifier []byte, kdf vault.KDFParams) error {
	_, err := tx.ExecContext(ctx,
		`INSERT INTO meta(key, value) VALUES (?, ?), (?, ?), (?, ?)
		 ON CONFLICT(key) DO UPDATE SET value = excluded.value`,
		metaSalt, salt, metaVerifier, verifier, metaKDF, []byte(kdf.String()))
	if err != nil {
		return fmt.Errorf("write key metadata: %w", err)
	}
	return nil
}

func (s *Store) initialize(ctx context.Context, passphrase []byte, kdf vault.KDFParams) error {
	c, salt, verifier, err := newKeyMaterial(passphrase, kdf)
	if err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	// A database without key material but with rows cannot be decrypted:
	// refuse rather than silently mixing keys.
	var n int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM credentials`).Scan(&n); err != nil {
		return err
	}
	if n > 0 {
		return errors.New("corrupted database: credentials present but key metadata missing")
	}
	if err := writeKeyMeta(ctx, tx, salt, verifier, kdf); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	s.cipher.Store(c)
	return nil
}

// Close releases the database and its lock.
func (s *Store) Close() error {
	err := s.db.Close()
	if lerr := s.lock.Close(); err == nil {
		err = lerr
	}
	return err
}

func aadFor(id int64) []byte { return []byte("credential:" + strconv.FormatInt(id, 10)) }

// List returns all credentials, without their content, ordered by name.
func (s *Store) List(ctx context.Context) ([]Credential, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, name, description, format, created_at, updated_at FROM credentials ORDER BY name`)
	if err != nil {
		return nil, fmt.Errorf("list credentials: %w", err)
	}
	defer rows.Close()
	out := []Credential{}
	for rows.Next() {
		var c Credential
		var created, updated int64
		if err := rows.Scan(&c.ID, &c.Name, &c.Description, &c.Format, &created, &updated); err != nil {
			return nil, fmt.Errorf("list credentials: %w", err)
		}
		c.CreatedAt, c.UpdatedAt = time.Unix(created, 0), time.Unix(updated, 0)
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list credentials: %w", err)
	}
	return out, nil
}

// Get returns the credential with the given id, content decrypted.
func (s *Store) Get(ctx context.Context, id int64) (*Credential, error) {
	return s.get(ctx, "id = ?", id)
}

// GetByName returns the credential with the given name, content decrypted.
func (s *Store) GetByName(ctx context.Context, name string) (*Credential, error) {
	return s.get(ctx, "name = ?", name)
}

func (s *Store) get(ctx context.Context, where string, arg any) (*Credential, error) {
	var c Credential
	var blob []byte
	var created, updated int64
	err := s.db.QueryRowContext(ctx,
		`SELECT id, name, description, format, credentials, created_at, updated_at FROM credentials WHERE `+where, arg).
		Scan(&c.ID, &c.Name, &c.Description, &c.Format, &blob, &created, &updated)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get credential: %w", err)
	}
	pt, err := s.cipher.Load().Decrypt(blob, aadFor(c.ID))
	if err != nil {
		return nil, fmt.Errorf("decrypt credential %d: %w", c.ID, err)
	}
	c.Content = string(pt)
	c.CreatedAt, c.UpdatedAt = time.Unix(created, 0), time.Unix(updated, 0)
	return &c, nil
}

// Create validates and inserts c, then sets its ID and timestamps.
func (s *Store) Create(ctx context.Context, c *Credential) error {
	if err := normalize(c); err != nil {
		return err
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// The AAD depends on the id assigned by SQLite: insert a placeholder,
	// then write the ciphertext within the same transaction.
	now := time.Now().Truncate(time.Second)
	res, err := tx.ExecContext(ctx,
		`INSERT INTO credentials(name, description, format, credentials, created_at, updated_at)
		 VALUES (?, ?, ?, x'', ?, ?)`,
		c.Name, c.Description, c.Format, now.Unix(), now.Unix())
	if err != nil {
		return mapConstraintError(err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return err
	}
	blob, err := s.cipher.Load().Encrypt([]byte(c.Content), aadFor(id))
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE credentials SET credentials = ? WHERE id = ?`, blob, id); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	c.ID, c.CreatedAt, c.UpdatedAt = id, now, now
	return nil
}

// Update validates c and replaces the stored credential with the same ID.
func (s *Store) Update(ctx context.Context, c *Credential) error {
	if err := normalize(c); err != nil {
		return err
	}
	blob, err := s.cipher.Load().Encrypt([]byte(c.Content), aadFor(c.ID))
	if err != nil {
		return err
	}
	res, err := s.db.ExecContext(ctx,
		`UPDATE credentials SET name = ?, description = ?, format = ?, credentials = ?, updated_at = ? WHERE id = ?`,
		c.Name, c.Description, c.Format, blob, time.Now().Unix(), c.ID)
	if err != nil {
		return mapConstraintError(err)
	}
	if n, err := res.RowsAffected(); err != nil {
		return err
	} else if n == 0 {
		return ErrNotFound
	}
	return nil
}

// Delete removes the credential with the given id.
func (s *Store) Delete(ctx context.Context, id int64) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM credentials WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("delete credential: %w", err)
	}
	if n, err := res.RowsAffected(); err != nil {
		return err
	} else if n == 0 {
		return ErrNotFound
	}
	return nil
}

// Rekey re-encrypts every credential with a key derived from newPassphrase
// and a fresh salt, in a single transaction: on error nothing is changed.
// It returns the number of credentials re-encrypted. Rekey must not run
// concurrently with Create or Update, which may still encrypt with the old key.
func (s *Store) Rekey(ctx context.Context, newPassphrase []byte, opts ...Option) (int, error) {
	o := options{kdf: vault.DefaultKDFParams}
	for _, opt := range opts {
		opt(&o)
	}
	if err := o.kdf.Validate(); err != nil {
		return 0, err
	}
	if len(newPassphrase) == 0 {
		return 0, errors.New("empty passphrase")
	}
	nc, salt, verifier, err := newKeyMaterial(newPassphrase, o.kdf)
	if err != nil {
		return 0, err
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	type row struct {
		id   int64
		blob []byte
	}
	var rows []row
	rs, err := tx.QueryContext(ctx, `SELECT id, credentials FROM credentials`)
	if err != nil {
		return 0, err
	}
	for rs.Next() {
		var r row
		if err := rs.Scan(&r.id, &r.blob); err != nil {
			rs.Close()
			return 0, err
		}
		rows = append(rows, r)
	}
	if err := rs.Close(); err != nil {
		return 0, err
	}
	if err := rs.Err(); err != nil {
		return 0, err
	}

	for _, r := range rows {
		pt, err := s.cipher.Load().Decrypt(r.blob, aadFor(r.id))
		if err != nil {
			return 0, fmt.Errorf("decrypt credential %d: %w", r.id, err)
		}
		blob, err := nc.Encrypt(pt, aadFor(r.id))
		if err != nil {
			return 0, err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE credentials SET credentials = ? WHERE id = ?`, blob, r.id); err != nil {
			return 0, err
		}
	}
	if err := writeKeyMeta(ctx, tx, salt, verifier, o.kdf); err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	s.cipher.Store(nc)
	// Flush the WAL into the main file and truncate it so that no copy of the
	// old ciphertexts is left behind (secure_delete zeroes freed pages).
	if _, err := s.db.ExecContext(ctx, `PRAGMA wal_checkpoint(TRUNCATE)`); err != nil {
		return len(rows), fmt.Errorf("checkpoint after rekey: %w", err)
	}
	return len(rows), nil
}

func normalize(c *Credential) error {
	c.Name = strings.TrimSpace(c.Name)
	c.Description = strings.TrimSpace(c.Description)
	c.Format = Format(strings.ToLower(strings.TrimSpace(string(c.Format))))
	if c.Format == "" {
		c.Format = FormatTXT
	}

	switch {
	case c.Name == "":
		return &ValidationError{"name", "is required"}
	case utf8.RuneCountInString(c.Name) > MaxNameLen:
		return &ValidationError{"name", fmt.Sprintf("must be at most %d characters", MaxNameLen)}
	case strings.ContainsRune(c.Name, '/'):
		return &ValidationError{"name", "must not contain '/'"}
	case strings.IndexFunc(c.Name, unicode.IsControl) >= 0:
		return &ValidationError{"name", "must not contain control characters"}
	case utf8.RuneCountInString(c.Description) > MaxDescriptionLen:
		return &ValidationError{"description", fmt.Sprintf("must be at most %d characters", MaxDescriptionLen)}
	case !utf8.ValidString(c.Name) || !utf8.ValidString(c.Description) || !utf8.ValidString(c.Content):
		return &ValidationError{"", "fields must be valid UTF-8"}
	case len(c.Content) > MaxContentSize:
		return &ValidationError{"credentials", fmt.Sprintf("must be at most %d bytes", MaxContentSize)}
	case !c.Format.Valid():
		return &ValidationError{"format", fmt.Sprintf("unknown format %q", c.Format)}
	}
	if err := c.Format.Validate(c.Content); err != nil {
		return &ValidationError{"credentials", err.Error()}
	}
	return nil
}

func mapConstraintError(err error) error {
	var se *sqlite.Error
	if errors.As(err, &se) && se.Code() == sqlite3.SQLITE_CONSTRAINT_UNIQUE {
		return &ValidationError{"name", "a credential with this name already exists"}
	}
	return err
}
