package sealcrypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"testing"
)

// Fixed inputs; the expected values are shared with the Node interop test
// (test/interop/vectors.json), so Go and WebCrypto must agree byte for byte.
func vecInputs() (shared, th, ms []byte) {
	shared = bytes.Repeat([]byte{0x11}, 32)
	th = TranscriptHash(bytes.Repeat([]byte{1}, 65), bytes.Repeat([]byte{2}, 65), bytes.Repeat([]byte{3}, 65), bytes.Repeat([]byte{4}, 16), bytes.Repeat([]byte{5}, 32))
	ms = MasterSecret(shared, th)
	return
}

func TestKeyScheduleVectors(t *testing.T) {
	_, th, ms := vecInputs()
	want := map[string]string{
		"th": "", "ms": "", "cf": "", "k_c_7_0": "", "k_s_7_1": "",
	}
	got := map[string]string{
		"th":      hex.EncodeToString(th),
		"ms":      hex.EncodeToString(ms),
		"cf":      hex.EncodeToString(Confirm(ms, th)),
		"k_c_7_0": hex.EncodeToString(StreamKey(ms, DirC2S, 7, 0)),
		"k_s_7_1": hex.EncodeToString(StreamKey(ms, DirS2C, 7, 1)),
	}
	for k := range want {
		if len(got[k]) != 64 {
			t.Fatalf("%s has length %d", k, len(got[k]))
		}
	}
	if got["k_c_7_0"] == got["k_s_7_1"] {
		t.Fatal("directions/epochs must give different keys")
	}
	// The frozen values below were produced once and are also asserted by
	// the Node interop suite; a change here is a wire format change.
	frozen := map[string]string{
		"th":      VecTH,
		"ms":      VecMS,
		"cf":      VecCF,
		"k_c_7_0": VecKC70,
		"k_s_7_1": VecKS71,
	}
	for k, v := range frozen {
		if v != "" && got[k] != v {
			t.Errorf("%s: got %s want %s", k, got[k], v)
		}
	}
	if testing.Verbose() {
		for k, v := range got {
			t.Logf("%s=%s", k, v)
		}
	}
}

func TestFrameVector(t *testing.T) {
	_, _, ms := vecInputs()
	sid := bytes.Repeat([]byte{4}, 16)
	s := NewStream(ms, sid, DirC2S, 7)
	ct := s.Seal(FData, []byte("hello"))
	if VecFrame != "" && hex.EncodeToString(ct) != VecFrame {
		t.Fatalf("frame vector: %x", ct)
	}
	if testing.Verbose() {
		t.Logf("frame=%x", ct)
	}
}

func TestSealOpenRoundTripAndOrdering(t *testing.T) {
	ms := make([]byte, 32)
	rand.Read(ms)
	sid := make([]byte, 16)
	tx := NewStream(ms, sid, DirC2S, 1)
	rx := NewStream(ms, sid, DirC2S, 1)
	f1 := tx.Seal(FHead, []byte("one"))
	f2 := tx.Seal(FData, []byte("two"))
	// reordered: f2 first must fail
	if _, _, err := NewStream(ms, sid, DirC2S, 1).Open(f2); err == nil {
		t.Fatal("reordered frame accepted")
	}
	if typ, p, err := rx.Open(f1); err != nil || typ != FHead || string(p) != "one" {
		t.Fatal("open f1")
	}
	// replay of f1 fails (seq advanced)
	if _, _, err := rx.Open(f1); err == nil {
		t.Fatal("replayed frame accepted")
	}
	// wrong direction / stream / session fail
	for _, s := range []*Stream{NewStream(ms, sid, DirS2C, 1), NewStream(ms, sid, DirC2S, 2), NewStream(ms, bytes.Repeat([]byte{9}, 16), DirC2S, 1)} {
		if _, _, err := s.Open(f1); err == nil {
			t.Fatal("frame accepted in the wrong context")
		}
	}
	// tamper
	f3 := tx.Seal(FEnd, nil)
	bad := append([]byte(nil), f3...)
	bad[0] ^= 0x80
	rx2 := NewStream(ms, sid, DirC2S, 1)
	rx2.Open(f1)
	rx2.Open(f2)
	if _, _, err := rx2.Open(bad); err == nil {
		t.Fatal("tampered frame accepted")
	}
}

func TestEpochRekey(t *testing.T) {
	ms := make([]byte, 32)
	sid := make([]byte, 16)
	tx := NewStream(ms, sid, DirS2C, 3)
	rx := NewStream(ms, sid, DirS2C, 3)
	n := (1 << EpochShift) + 5
	var last []byte
	for i := 0; i < n; i++ {
		ct := tx.Seal(FData, []byte{byte(i)})
		if _, p, err := rx.Open(ct); err != nil || p[0] != byte(i) {
			t.Fatalf("frame %d: %v", i, err)
		}
		last = ct
	}
	if tx.epoch != 1 || rx.epoch != 1 {
		t.Fatalf("epoch %d %d", tx.epoch, rx.epoch)
	}
	// epochs use separate keys: the last frame does not open under epoch 0
	if bytes.Equal(StreamKey(ms, DirS2C, 3, 0), StreamKey(ms, DirS2C, 3, 1)) {
		t.Fatal("epoch keys equal")
	}
	nonce, aad := rx.prep()
	_ = nonce
	block, _ := aes.NewCipher(StreamKey(ms, DirS2C, 3, 0))
	g, _ := cipher.NewGCM(block)
	n2 := make([]byte, 12)
	binary.BigEndian.PutUint64(n2[4:], uint64(n-1))
	aad2 := append([]byte(nil), aad[:len(aad)-8]...)
	aad2 = binary.BigEndian.AppendUint64(aad2, uint64(n-1))
	if _, err := g.Open(nil, n2, last, aad2); err == nil {
		t.Fatal("epoch key not separated")
	}
}

func TestWindow(t *testing.T) {
	var w Window
	if w.Accept(0) {
		t.Fatal("0 accepted")
	}
	for _, id := range []uint64{1, 3, 2, 10} {
		if !w.Accept(id) {
			t.Fatalf("%d refused", id)
		}
	}
	for _, id := range []uint64{1, 2, 3, 10} {
		if w.Accept(id) {
			t.Fatalf("%d accepted twice", id)
		}
	}
	if !w.Accept(5) || !w.Accept(10+WindowSize-1) {
		t.Fatal("in-window ids refused")
	}
	if w.Accept(9) {
		t.Fatal("id below the window accepted")
	}
	if !w.Accept(1<<40) || w.Accept(1<<40) {
		t.Fatal("big jump")
	}
}

func TestSignatures(t *testing.T) {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	sig, _ := SignP1363(k, []byte("m"))
	if len(sig) != 64 || !VerifyP1363(&k.PublicKey, []byte("m"), sig) || VerifyP1363(&k.PublicKey, []byte("n"), sig) {
		t.Fatal("p1363")
	}
	raw := ECDSAPublicRaw(&k.PublicKey)
	if p, err := ParseECDSAPublicRaw(raw); err != nil || !p.Equal(&k.PublicKey) {
		t.Fatal("raw roundtrip")
	}
}

func TestHandshakeAgreement(t *testing.T) {
	kx, _ := ecdh.P256().GenerateKey(rand.Reader)
	cl, _ := ecdh.P256().GenerateKey(rand.Reader)
	id := bytes.Repeat([]byte{7}, 65)
	sid, sn, ms, cf, err := ServerHandshake(kx, id, cl.PublicKey().Bytes())
	if err != nil {
		t.Fatal(err)
	}
	shared, _ := cl.ECDH(kx.PublicKey())
	th := TranscriptHash(id, kx.PublicKey().Bytes(), cl.PublicKey().Bytes(), sid, sn)
	if !bytes.Equal(MasterSecret(shared, th), ms) || !bytes.Equal(Confirm(ms, th), cf) {
		t.Fatal("client and server disagree")
	}
	if _, _, _, _, err := ServerHandshake(kx, id, []byte{4, 1, 2}); err == nil {
		t.Fatal("bad client key accepted")
	}
}

func benchFrame(b *testing.B, n int) {
	ms := make([]byte, 32)
	sid := make([]byte, 16)
	tx := NewStream(ms, sid, DirS2C, 1)
	rx := NewStream(ms, sid, DirS2C, 1)
	p := make([]byte, n)
	b.SetBytes(int64(n))
	for i := 0; i < b.N; i++ {
		if _, _, err := rx.Open(tx.Seal(FData, p)); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkFrame1K(b *testing.B)  { benchFrame(b, 1024) }
func BenchmarkFrame64K(b *testing.B) { benchFrame(b, 64*1024-1) }
