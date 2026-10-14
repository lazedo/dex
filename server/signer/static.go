package signer

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"

	"github.com/go-jose/go-jose/v4"
)

// StaticConfig holds configuration for the static signer: keys kept outside
// Dex, in a file (such as a mounted Secret), the same for every instance
// that reads it, and never rotated by Dex. Rotating is replacing the file;
// the signer reloads it when it changes.
type StaticConfig struct {
	// KeysFile is a JSON file with the keys, in the shape the storages keep
	// them in: signingKey (a private JWK), signingKeyPub (derived from
	// signingKey when absent) and verificationKeys (older public keys still
	// accepted, each as {"publicKey": JWK}). An exported Kubernetes storage
	// signing key object reads as one.
	KeysFile string `json:"keysFile"`
}

// staticReloadInterval is how often the static signer looks at its file.
var staticReloadInterval = 30 * time.Second

// Open loads the keys.
func (c *StaticConfig) Open(logger *slog.Logger) (Signer, error) {
	if c.KeysFile == "" {
		return nil, errors.New("signer.config.keysFile must be specified")
	}
	s := &staticSigner{file: c.KeysFile, logger: logger}
	if err := s.load(); err != nil {
		return nil, err
	}
	return s, nil
}

type staticKeys struct {
	SigningKey       *jose.JSONWebKey `json:"signingKey"`
	SigningKeyPub    *jose.JSONWebKey `json:"signingKeyPub"`
	VerificationKeys []struct {
		PublicKey *jose.JSONWebKey `json:"publicKey"`
	} `json:"verificationKeys"`
}

// staticSigner signs with the keys of its file.
type staticSigner struct {
	file   string
	logger *slog.Logger

	mu      sync.RWMutex
	mtime   time.Time
	signing *jose.JSONWebKey
	alg     jose.SignatureAlgorithm
	public  []*jose.JSONWebKey
}

func (s *staticSigner) load() error {
	st, err := os.Stat(s.file)
	if err != nil {
		return fmt.Errorf("static signer keys: %v", err)
	}
	b, err := os.ReadFile(s.file)
	if err != nil {
		return fmt.Errorf("static signer keys: %v", err)
	}
	var keys staticKeys
	if err := json.Unmarshal(b, &keys); err != nil {
		return fmt.Errorf("static signer keys %s: %v", s.file, err)
	}
	if keys.SigningKey == nil || keys.SigningKey.IsPublic() {
		return fmt.Errorf("static signer keys %s: signingKey must be a private key", s.file)
	}
	alg, err := signatureAlgorithm(keys.SigningKey)
	if err != nil {
		return fmt.Errorf("static signer keys %s: %v", s.file, err)
	}
	pub := keys.SigningKeyPub
	if pub == nil {
		p := keys.SigningKey.Public()
		pub = &p
	}
	if pub.KeyID == "" {
		pub.KeyID = keys.SigningKey.KeyID
	}
	public := []*jose.JSONWebKey{pub}
	for _, v := range keys.VerificationKeys {
		if v.PublicKey != nil {
			public = append(public, v.PublicKey)
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.mtime, s.signing, s.alg, s.public = st.ModTime(), keys.SigningKey, alg, public
	return nil
}

// Start reloads the keys when their file changes, until the context ends.
func (s *staticSigner) Start(ctx context.Context) {
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-time.After(staticReloadInterval):
				s.reloadIfChanged()
			}
		}
	}()
}

func (s *staticSigner) reloadIfChanged() {
	st, err := os.Stat(s.file)
	if err != nil {
		s.logger.Error("static signer keys unreadable, keeping the loaded ones", "file", s.file, "err", err)
		return
	}
	s.mu.RLock()
	same := st.ModTime().Equal(s.mtime)
	s.mu.RUnlock()
	if same {
		return
	}
	if err := s.load(); err != nil {
		s.logger.Error("static signer keys not reloaded, keeping the loaded ones", "file", s.file, "err", err)
		return
	}
	s.logger.Info("static signer keys reloaded", "file", s.file)
}

func (s *staticSigner) Sign(_ context.Context, payload []byte) (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return signPayload(s.signing, s.alg, payload)
}

func (s *staticSigner) ValidationKeys(_ context.Context) ([]*jose.JSONWebKey, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]*jose.JSONWebKey(nil), s.public...), nil
}

func (s *staticSigner) Algorithm(_ context.Context) (jose.SignatureAlgorithm, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.alg, nil
}
