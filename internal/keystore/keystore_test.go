package keystore

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCreatePersistAndPermissions(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	b := s.Bundle()
	if _, err := VerifyBundle(b, "", time.Now()); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"identity.pem", "kx.json"} {
		st, err := os.Stat(filepath.Join(dir, f))
		if err != nil || st.Mode().Perm() != 0o600 {
			t.Fatalf("%s mode %v %v", f, st.Mode(), err)
		}
	}
	s2, err := Open(dir, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if s2.Bundle().FP != b.FP || s2.Bundle().KX.KID != b.KX.KID {
		t.Fatal("keys not persisted")
	}
	if _, ok := s2.KX(b.KX.KID); !ok {
		t.Fatal("kx lookup")
	}
}

func TestKXRotationSchedule(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	clock := func() time.Time { return now }
	s, _ := OpenWithClock(t.TempDir(), time.Hour, clock)
	first := s.Bundle().KX
	now = now.Add(61 * time.Minute)
	if changed, _ := s.Maintain(); !changed {
		t.Fatal("no rotation after one period")
	}
	second := s.Bundle().KX
	if second.KID == first.KID {
		t.Fatal("same key after rotation")
	}
	if _, ok := s.KX(first.KID); !ok {
		t.Fatal("previous key must stay usable for one more period")
	}
	now = now.Add(4 * time.Hour)
	s.Maintain()
	if _, ok := s.KX(first.KID); ok {
		t.Fatal("expired key still accepted")
	}
	if _, err := VerifyBundle(s.Bundle(), s.Fingerprint(), now); err != nil {
		t.Fatal(err)
	}
}

func TestIdentityRotationAndTOFU(t *testing.T) {
	s, _ := Open(t.TempDir(), time.Hour)
	pinned := s.Fingerprint()
	s.RotateIdentity()
	s.RotateIdentity()
	b := s.Bundle()
	if b.FP == pinned {
		t.Fatal("identity did not change")
	}
	fp, err := VerifyBundle(b, pinned, time.Now())
	if err != nil || fp != b.FP {
		t.Fatalf("signed rotation chain refused: %v", err)
	}
	// a different server (key swap by a middle box) is refused
	other, _ := Open(t.TempDir(), time.Hour)
	if _, err := VerifyBundle(other.Bundle(), pinned, time.Now()); err == nil || !strings.Contains(err.Error(), "SEAL_TOFU_MISMATCH") {
		t.Fatalf("key swap accepted: %v", err)
	}
	// a forged link is refused
	bad := s.Bundle()
	bad.Chain = append([]Link(nil), bad.Chain...)
	bad.Chain[0].Sig = bad.Chain[1].Sig
	if _, err := VerifyBundle(bad, pinned, time.Now()); err == nil {
		t.Fatal("forged rotation accepted")
	}
	// a kx certificate signed by another identity is refused
	mixed := other.Bundle()
	mixed.KX = s.Bundle().KX
	if _, err := VerifyBundle(mixed, "", time.Now()); err == nil {
		t.Fatal("kx certificate from another identity accepted")
	}
	// expired kx refused
	if _, err := VerifyBundle(s.Bundle(), "", time.Now().Add(30*24*time.Hour)); err == nil {
		t.Fatal("expired kx accepted")
	}
}
