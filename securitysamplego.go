// Mixed safe and unsafe examples for static scan tests only.
package main

import (
	"crypto/md5"      // insecure for passwords
	"database/sql"
	"errors"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"

	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"
)

var dataRoot = "/var/app/data"

func getUserSafe(db *sql.DB, name string) (*User, error) {
	row := db.QueryRow("SELECT id, name FROM users WHERE name = ?", name)
	u := &User{}
	if err := row.Scan(&u.ID, &u.Name); err != nil {
		return nil, err
	}
	return u, nil
}

func getUserUnsafe(db *sql.DB, name string) (*User, error) {
	// SQL injection via concatenation
	q := "SELECT id, name FROM users WHERE name = '" + name + "'"
	row := db.QueryRow(q)
	u := &User{}
	if err := row.Scan(&u.ID, &u.Name); err != nil {
		return nil, err
	}
	return u, nil
}

type User struct {
	ID   int
	Name string
}

// ---------- File serving ----------

func serveFileSafe(w http.ResponseWriter, r *http.Request) {
	f := r.URL.Query().Get("f")
	clean := filepath.Clean("/" + f) // normalize
	full := filepath.Join(dataRoot, clean)
	if !strings.HasPrefix(full, dataRoot+string(filepath.Separator)) {
		http.Error(w, "invalid path", http.StatusBadRequest)
		return
	}
	http.ServeFile(w, r, full)
}

func serveFileUnsafe(w http.ResponseWriter, r *http.Request) {
	// path traversal: user controls full path suffix
	f := r.URL.Query().Get("f")
	http.ServeFile(w, r, dataRoot+"/"+f)
}

// ---------- Redirects ----------

func redirectSafe(w http.ResponseWriter, r *http.Request) {
	next := r.URL.Query().Get("next")
	u, err := url.Parse(next)
	if err != nil || u.Host != "example.com" {
		http.Error(w, "bad redirect", http.StatusBadRequest)
		return
	}
	http.Redirect(w, r, u.String(), http.StatusFound)
}

func redirectUnsafe(w http.ResponseWriter, r *http.Request) {
	// open redirect
	http.Redirect(w, r, r.URL.Query().Get("next"), http.StatusFound)
}

// ---------- Password hashing ----------

func hashPasswordSafe(pw string) (string, error) {
	b, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
	return string(b), err
}

func hashPasswordUnsafe(pw string) string {
	// fast, reversible-ish fingerprinting inappropriate for passwords
	return string(md5.Sum([]byte(pw))[:])
}

// ---------- TLS / HTTP client (skipped actual request to keep file self-contained) ----------

type client struct {
	skipVerify bool
}

func newClientSafe() *client {
	return &client{skipVerify: false}
}

func newClientUnsafe() *client {
	// would disable TLS verification in a real http.Transport
	return &client{skipVerify: true}
}

// ---------- Misc ----------

func must(err error) {
	if err != nil {
		panic(err)
	}
}

func maybe(err error) error {
	if err != nil {
		return errors.New("wrapped: " + err.Error())
	}
	return nil
}
