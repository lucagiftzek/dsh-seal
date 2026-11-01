// Package keystore owns the server keys of dsh-seal: the long-term identity
// key (ECDSA P-256), the signed chain of identity rotations, and the key
// exchange keys (ECDH P-256) that rotate on a schedule, each one signed by the
// identity key. Everything secret is written 0600 under the state directory.
package keystore

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	sc "dsh-seal/internal/sealcrypto"
)

// MaxChain bounds the rotation chain shipped to clients.
const MaxChain = 8

// Link is one signed identity rotation: Prev hands over to Next.
type Link struct {
	Prev string `json:"prev"`
	Next string `json:"next"`
	T    uint64 `json:"t"`
	Sig  string `json:"sig"`
}

// KXCert is the public, signed description of a key exchange key.
type KXCert struct {
	KID string `json:"kid"`
	Pub string `json:"pub"`
	NBF uint64 `json:"nbf"`
	Exp uint64 `json:"exp"`
	Sig string `json:"sig"`
}

// Bundle is what every page load receives (inside boot.js and sw.js).
type Bundle struct {
	V     int    `json:"v"`
	ID    string `json:"id"`
	FP    string `json:"fp"`
	Chain []Link `json:"chain"`
	KX    KXCert `json:"kx"`
}

type kxKey struct {
	priv *ecdh.PrivateKey
	cert KXCert
}

type kxFile struct {
	Priv string `json:"priv"`
	NBF  uint64 `json:"nbf"`
	Exp  uint64 `json:"exp"`
	Sig  string `json:"sig"`
}

// Store is safe for concurrent use.
type Store struct {
	dir    string
	period time.Duration
	now    func() time.Time

	mu    sync.RWMutex
	id    *ecdsa.PrivateKey
	idRaw []byte
	chain []Link
	kx    []*kxKey // newest last
}

// Open loads or creates the keys under dir. period is the key exchange key
// rotation period; each key stays valid for two periods so pages loaded just
// before a rotation keep working.
func Open(dir string, period time.Duration) (*Store, error) {
	return OpenWithClock(dir, period, time.Now)
}

// OpenWithClock is Open with an injectable clock (tests).
func OpenWithClock(dir string, period time.Duration, now func() time.Time) (*Store, error) {
	if period <= 0 {
		period = 7 * 24 * time.Hour
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("SEAL_KEYS_DIR: %w", err)
	}
	s := &Store{dir: dir, period: period, now: now}
	if err := s.loadIdentity(); err != nil {
		return nil, err
	}
	if err := s.loadChain(); err != nil {
		return nil, err
	}
	if err := s.loadKX(); err != nil {
		return nil, err
	}
	if _, err := s.Maintain(); err != nil {
		return nil, err
	}
	return s, nil
}

func writeSecret(path string, data []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func (s *Store) loadIdentity() error {
	p := filepath.Join(s.dir, "identity.pem")
	b, err := os.ReadFile(p)
	if errors.Is(err, os.ErrNotExist) {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return err
		}
		if err := s.saveIdentity(k); err != nil {
			return err
		}
		s.id, s.idRaw = k, sc.ECDSAPublicRaw(&k.PublicKey)
		return nil
	}
	if err != nil {
		return fmt.Errorf("SEAL_KEYS_READ: %w", err)
	}
	blk, _ := pem.Decode(b)
	if blk == nil {
		return errors.New("SEAL_KEYS_READ: identity.pem is not PEM")
	}
	k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		return fmt.Errorf("SEAL_KEYS_READ: %w", err)
	}
	ek, ok := k.(*ecdsa.PrivateKey)
	if !ok || ek.Curve != elliptic.P256() {
		return errors.New("SEAL_KEYS_READ: identity.pem is not an ECDSA P-256 key")
	}
	s.id, s.idRaw = ek, sc.ECDSAPublicRaw(&ek.PublicKey)
	return nil
}

func (s *Store) saveIdentity(k *ecdsa.PrivateKey) error {
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		return err
	}
	return writeSecret(filepath.Join(s.dir, "identity.pem"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

func (s *Store) loadChain() error {
	b, err := os.ReadFile(filepath.Join(s.dir, "chain.json"))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("SEAL_KEYS_READ: %w", err)
	}
	return json.Unmarshal(b, &s.chain)
}

func (s *Store) loadKX() error {
	b, err := os.ReadFile(filepath.Join(s.dir, "kx.json"))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("SEAL_KEYS_READ: %w", err)
	}
	var files []kxFile
	if err := json.Unmarshal(b, &files); err != nil {
		return fmt.Errorf("SEAL_KEYS_READ: kx.json: %w", err)
	}
	for _, f := range files {
		raw, err := sc.B64.DecodeString(f.Priv)
		if err != nil {
			return fmt.Errorf("SEAL_KEYS_READ: kx.json: %w", err)
		}
		priv, err := ecdh.P256().NewPrivateKey(raw)
		if err != nil {
			return fmt.Errorf("SEAL_KEYS_READ: kx.json: %w", err)
		}
		pub := priv.PublicKey().Bytes()
		s.kx = append(s.kx, &kxKey{priv: priv, cert: KXCert{KID: sc.KID(pub), Pub: sc.B64.EncodeToString(pub), NBF: f.NBF, Exp: f.Exp, Sig: f.Sig}})
	}
	sort.Slice(s.kx, func(i, j int) bool { return s.kx[i].cert.NBF < s.kx[j].cert.NBF })
	return nil
}

func (s *Store) saveKX() error {
	files := make([]kxFile, 0, len(s.kx))
	for _, k := range s.kx {
		files = append(files, kxFile{Priv: sc.B64.EncodeToString(k.priv.Bytes()), NBF: k.cert.NBF, Exp: k.cert.Exp, Sig: k.cert.Sig})
	}
	b, _ := json.MarshalIndent(files, "", "  ")
	return writeSecret(filepath.Join(s.dir, "kx.json"), b)
}

// signKX (re)signs a key exchange key with the current identity.
func (s *Store) signKX(priv *ecdh.PrivateKey, nbf, exp uint64) (*kxKey, error) {
	pub := priv.PublicKey().Bytes()
	sig, err := sc.SignP1363(s.id, sc.KXCertMessage(pub, nbf, exp))
	if err != nil {
		return nil, err
	}
	return &kxKey{priv: priv, cert: KXCert{KID: sc.KID(pub), Pub: sc.B64.EncodeToString(pub), NBF: nbf, Exp: exp, Sig: sc.B64.EncodeToString(sig)}}, nil
}

// Maintain drops expired key exchange keys and creates a new one when the
// newest is older than one period. It reports whether anything changed.
func (s *Store) Maintain() (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := uint64(s.now().Unix())
	changed := false
	kept := s.kx[:0]
	for _, k := range s.kx {
		if k.cert.Exp > now {
			kept = append(kept, k)
		} else {
			changed = true
		}
	}
	s.kx = kept
	per := uint64(s.period / time.Second)
	if len(s.kx) == 0 || s.kx[len(s.kx)-1].cert.NBF+per <= now {
		priv, err := ecdh.P256().GenerateKey(rand.Reader)
		if err != nil {
			return false, err
		}
		k, err := s.signKX(priv, now, now+2*per)
		if err != nil {
			return false, err
		}
		s.kx = append(s.kx, k)
		changed = true
	}
	if changed {
		if err := s.saveKX(); err != nil {
			return false, fmt.Errorf("SEAL_KEYS_WRITE: %w", err)
		}
	}
	return changed, nil
}

// RotateIdentity replaces the identity key with a new one, signed by the old
// one, and re-signs every live key exchange key with the new identity.
func (s *Store) RotateIdentity() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	next, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	nextRaw := sc.ECDSAPublicRaw(&next.PublicKey)
	t := uint64(s.now().Unix())
	sig, err := sc.SignP1363(s.id, sc.RotationMessage(s.idRaw, nextRaw, t))
	if err != nil {
		return err
	}
	s.chain = append(s.chain, Link{Prev: sc.B64.EncodeToString(s.idRaw), Next: sc.B64.EncodeToString(nextRaw), T: t, Sig: sc.B64.EncodeToString(sig)})
	if len(s.chain) > MaxChain {
		s.chain = s.chain[len(s.chain)-MaxChain:]
	}
	s.id, s.idRaw = next, nextRaw
	for i, k := range s.kx {
		nk, err := s.signKX(k.priv, k.cert.NBF, k.cert.Exp)
		if err != nil {
			return err
		}
		s.kx[i] = nk
	}
	cb, _ := json.MarshalIndent(s.chain, "", "  ")
	if err := writeSecret(filepath.Join(s.dir, "chain.json"), cb); err != nil {
		return err
	}
	if err := s.saveIdentity(next); err != nil {
		return err
	}
	return s.saveKX()
}

// Bundle returns the public bundle for a page load (current key exchange key).
func (s *Store) Bundle() Bundle {
	s.mu.RLock()
	defer s.mu.RUnlock()
	chain := append([]Link(nil), s.chain...)
	return Bundle{V: 1, ID: sc.B64.EncodeToString(s.idRaw), FP: sc.Fingerprint(s.idRaw), Chain: chain, KX: s.kx[len(s.kx)-1].cert}
}

// IdentityRaw returns the current identity public key (65 bytes).
func (s *Store) IdentityRaw() []byte {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]byte(nil), s.idRaw...)
}

// Fingerprint of the current identity.
func (s *Store) Fingerprint() string { return sc.Fingerprint(s.IdentityRaw()) }

// KX finds a live key exchange key by id. A small grace after expiry lets a
// page that loaded just before the expiry finish its handshake.
func (s *Store) KX(kid string) (*ecdh.PrivateKey, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	now := uint64(s.now().Unix())
	for _, k := range s.kx {
		if k.cert.KID == kid && now < k.cert.Exp+3600 {
			return k.priv, true
		}
	}
	return nil, false
}

// VerifyBundle is the reference implementation of the client checks: the key
// exchange certificate must be signed by the bundle identity, and when trusted
// (a previously pinned fingerprint) differs from the bundle identity, a valid
// chain of rotations must lead from trusted to it. It returns the fingerprint
// the client should pin afterwards.
func VerifyBundle(b Bundle, trusted string, now time.Time) (string, error) {
	idRaw, err := sc.B64.DecodeString(b.ID)
	if err != nil {
		return "", errors.New("SEAL_BUNDLE_INVALID: id")
	}
	idPub, err := sc.ParseECDSAPublicRaw(idRaw)
	if err != nil {
		return "", errors.New("SEAL_BUNDLE_INVALID: id key")
	}
	fp := sc.Fingerprint(idRaw)
	if fp != b.FP {
		return "", errors.New("SEAL_BUNDLE_INVALID: fingerprint")
	}
	kxRaw, err1 := sc.B64.DecodeString(b.KX.Pub)
	sig, err2 := sc.B64.DecodeString(b.KX.Sig)
	if err1 != nil || err2 != nil || !sc.VerifyP1363(idPub, sc.KXCertMessage(kxRaw, b.KX.NBF, b.KX.Exp), sig) {
		return "", errors.New("SEAL_BUNDLE_INVALID: key exchange signature")
	}
	if uint64(now.Unix()) > b.KX.Exp+86400 {
		return "", errors.New("SEAL_BUNDLE_EXPIRED: key exchange key expired")
	}
	if trusted == "" || trusted == fp {
		return fp, nil
	}
	cur := trusted
	for _, l := range b.Chain {
		prevRaw, e1 := sc.B64.DecodeString(l.Prev)
		if e1 != nil || sc.Fingerprint(prevRaw) != cur {
			continue
		}
		nextRaw, e2 := sc.B64.DecodeString(l.Next)
		lsig, e3 := sc.B64.DecodeString(l.Sig)
		prevPub, e4 := sc.ParseECDSAPublicRaw(prevRaw)
		if e2 != nil || e3 != nil || e4 != nil || !sc.VerifyP1363(prevPub, sc.RotationMessage(prevRaw, nextRaw, l.T), lsig) {
			return "", errors.New("SEAL_TOFU_MISMATCH: invalid rotation link")
		}
		cur = sc.Fingerprint(nextRaw)
		if cur == fp {
			return fp, nil
		}
	}
	return "", errors.New("SEAL_TOFU_MISMATCH: identity changed without a signed rotation")
}
