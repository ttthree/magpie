package agent

// Eureka keeps its secrets in ~/.eureka/credentials.enc: one AES-256-GCM
// blob whose key is derived from this machine's identity. magpie reads the
// store, sets one entry (its custom-model endpoint list) and seals it back,
// leaving every other credential and an unreadable store alone.
//
// The format is Eureka's own (packages/shared/src/credentials/backends/
// secure-storage.ts): a 64-byte header ("CRAFT01\0", flags, a 32-byte salt),
// then IV, auth tag and ciphertext. The key is PBKDF2-SHA256 over
// sha256(hostname + username + homedir + "craft-agent-v1").

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"time"

	"github.com/yetone/magpie/internal/edit"
)

const (
	eurekaMagic      = "CRAFT01\x00"
	eurekaHeaderSize = 64
	eurekaSaltOffset = 12
	eurekaSaltSize   = 32
	eurekaIVSize     = 12
	eurekaTagSize    = 16
	eurekaKeySize    = 32
	eurekaIterations = 100000
)

// eurekaMachineKey derives the password Eureka seals its store with from
// this machine's identity, spelled exactly as Eureka does.
func eurekaMachineKey() string {
	host, _ := os.Hostname()
	name := ""
	if u, err := user.Current(); err == nil {
		name = u.Username
	}
	home, _ := os.UserHomeDir()
	sum := sha256.New()
	sum.Write([]byte(host))
	sum.Write([]byte(name))
	sum.Write([]byte(home))
	sum.Write([]byte("craft-agent-v1"))
	return string(sum.Sum(nil))
}

// eurekaOpenStore reads dir's sealed store: the store, its salt, or (nil,
// nil, nil) when there is no file yet. A store magpie cannot decrypt is an
// error, never treated as empty.
func eurekaOpenStore(dir string) (map[string]json.RawMessage, []byte, error) {
	raw, err := os.ReadFile(filepath.Join(dir, "credentials.enc"))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil, nil
		}
		return nil, nil, err
	}
	return eurekaOpen(raw)
}

// eurekaOpen decrypts a store. A nil store (no file) comes back as nil.
func eurekaOpen(raw []byte) (map[string]json.RawMessage, []byte, error) {
	if raw == nil {
		return nil, nil, nil
	}
	if len(raw) < eurekaHeaderSize+eurekaIVSize+eurekaTagSize || string(raw[:len(eurekaMagic)]) != eurekaMagic {
		return nil, nil, errors.New("Eureka's credentials.enc is not a store magpie understands")
	}
	salt := raw[eurekaSaltOffset : eurekaSaltOffset+eurekaSaltSize]
	key, err := pbkdf2.Key(sha256.New, eurekaMachineKey(), salt, eurekaIterations, eurekaKeySize)
	if err != nil {
		return nil, nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}
	iv := raw[eurekaHeaderSize : eurekaHeaderSize+eurekaIVSize]
	tag := raw[eurekaHeaderSize+eurekaIVSize : eurekaHeaderSize+eurekaIVSize+eurekaTagSize]
	ct := raw[eurekaHeaderSize+eurekaIVSize+eurekaTagSize:]
	// Go's Open wants ciphertext with the tag appended; Eureka writes the
	// tag first.
	sealed := append(append([]byte(nil), ct...), tag...)
	plain, err := gcm.Open(nil, iv, sealed, nil)
	if err != nil {
		return nil, nil, errors.New("Eureka's credentials.enc can't be opened (another machine sealed it)")
	}
	var store map[string]json.RawMessage
	if json.Unmarshal(plain, &store) != nil {
		return nil, nil, errors.New("Eureka's credentials.enc is not JSON magpie can read")
	}
	return store, salt, nil
}

// eurekaSeal encrypts a store under salt (a fresh one when nil).
func eurekaSeal(store map[string]json.RawMessage, salt []byte) ([]byte, error) {
	if salt == nil {
		salt = make([]byte, eurekaSaltSize)
		if _, err := rand.Read(salt); err != nil {
			return nil, err
		}
	}
	key, err := pbkdf2.Key(sha256.New, eurekaMachineKey(), salt, eurekaIterations, eurekaKeySize)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	plain, err := json.Marshal(store)
	if err != nil {
		return nil, err
	}
	iv := make([]byte, eurekaIVSize)
	if _, err := rand.Read(iv); err != nil {
		return nil, err
	}
	sealed := gcm.Seal(nil, iv, plain, nil)
	ct, tag := sealed[:len(sealed)-eurekaTagSize], sealed[len(sealed)-eurekaTagSize:]
	header := make([]byte, eurekaHeaderSize)
	copy(header, eurekaMagic)
	copy(header[eurekaSaltOffset:], salt)
	out := append(header, iv...)
	out = append(out, tag...)
	return append(out, ct...), nil
}

// newEurekaStore is a fresh store, as Eureka makes one.
func newEurekaStore() map[string]json.RawMessage {
	now := strconv.FormatInt(time.Now().UnixMilli(), 10)
	return map[string]json.RawMessage{
		"version":  json.RawMessage("1"),
		"metadata": json.RawMessage(`{"createdAt":` + now + `,"updatedAt":` + now + `}`),
	}
}

// eurekaCredentials is the credentials map inside the store, never nil.
func eurekaCredentials(store map[string]json.RawMessage) (map[string]json.RawMessage, error) {
	creds := map[string]json.RawMessage{}
	if raw, ok := store["credentials"]; ok {
		if err := json.Unmarshal(raw, &creds); err != nil {
			return nil, errors.New("Eureka's credentials.enc has a credentials list magpie can't read")
		}
	}
	return creds, nil
}

// eurekaCredValue is a credential's value, "" when it is missing.
func eurekaCredValue(creds map[string]json.RawMessage, account string) string {
	var v struct {
		Value string `json:"value"`
	}
	if json.Unmarshal(creds[account], &v) != nil {
		return ""
	}
	return v.Value
}

// eurekaSetCredValue sets a credential's value, keeping its other fields.
func eurekaSetCredValue(creds map[string]json.RawMessage, account, value string) {
	entry := map[string]json.RawMessage{}
	if raw, ok := creds[account]; ok {
		_ = json.Unmarshal(raw, &entry)
	}
	entry["value"] = json.RawMessage(strconv.Quote(value))
	b, err := json.Marshal(entry)
	if err != nil {
		return
	}
	creds[account] = b
}

// eurekaSaveStore seals creds into the store and writes it back, creating the
// file 0600 and bumping metadata.updatedAt.
func eurekaSaveStore(dir string, store, creds map[string]json.RawMessage, salt []byte) error {
	b, err := json.Marshal(creds)
	if err != nil {
		return err
	}
	store["credentials"] = b
	eurekaTouch(store)
	data, err := eurekaSeal(store, salt)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	path := filepath.Join(dir, "credentials.enc")
	if err := edit.WriteAtomic(path, data); err != nil {
		return err
	}
	return os.Chmod(path, 0o600)
}

// eurekaTouch bumps metadata.updatedAt, keeping whatever else it says.
func eurekaTouch(store map[string]json.RawMessage) {
	meta := map[string]json.RawMessage{}
	if raw, ok := store["metadata"]; ok {
		if json.Unmarshal(raw, &meta) != nil {
			meta = map[string]json.RawMessage{}
		}
	}
	meta["updatedAt"] = json.RawMessage(strconv.FormatInt(time.Now().UnixMilli(), 10))
	if b, err := json.Marshal(meta); err == nil {
		store["metadata"] = b
	}
}
