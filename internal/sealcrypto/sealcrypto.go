// Package sealcrypto holds the dsh-seal key schedule and the frame cipher.
//
// Every primitive is chosen so that a browser can reproduce it with WebCrypto
// alone: ECDH P-256 (raw 65 byte public keys, the shared secret is the 32 byte
// x coordinate), ECDSA P-256 with SHA-256 (IEEE P1363 r||s signatures),
// HKDF-SHA256 and AES-256-GCM. docs/PROTOCOL.md is the normative description.
package sealcrypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
)

// Label prefixes every context string, so keys from this protocol can never
// collide with keys derived for anything else.
const Label = "dsh-seal/1"

// Directions of a stream. They appear in key derivation and in the AAD.
const (
	DirC2S byte = 'c'
	DirS2C byte = 's'
)

// Frame types. The high bit (FlagMore) marks a fragment that continues.
const (
	FHead  byte = 0x01
	FData  byte = 0x02
	FEnd   byte = 0x03
	FError byte = 0x04
)

const (
	// EpochShift: a new AES key every 2^16 frames of one stream direction.
	EpochShift = 16
	// MaxPayload is the largest plaintext payload of one frame.
	MaxPayload = 64 * 1024
	// MaxFrame bounds a ciphertext frame (type byte + payload + tag + slack).
	MaxFrame = MaxPayload + 64
)

var (
	ErrAuth     = errors.New("SEAL_FRAME_AUTH: frame failed authentication")
	ErrTooLarge = errors.New("SEAL_FRAME_TOO_LARGE: frame exceeds the size limit")
	ErrEmpty    = errors.New("SEAL_FRAME_EMPTY: frame has no type byte")
)

// B64 is unpadded base64url, the only text encoding of binary on the wire.
var B64 = base64.RawURLEncoding

// Curve helpers ------------------------------------------------------------

// ECDSAPublicRaw encodes an ECDSA P-256 public key as 65 uncompressed bytes.
func ECDSAPublicRaw(pub *ecdsa.PublicKey) []byte {
	b, err := pub.Bytes()
	if err != nil {
		panic(err)
	}
	return b
}

// ParseECDSAPublicRaw decodes 65 uncompressed bytes into an ECDSA P-256 key.
func ParseECDSAPublicRaw(raw []byte) (*ecdsa.PublicKey, error) {
	return ecdsa.ParseUncompressedPublicKey(elliptic.P256(), raw)
}

// SignP1363 signs SHA-256(msg) and returns the fixed 64 byte r||s form that
// WebCrypto produces and expects.
func SignP1363(priv *ecdsa.PrivateKey, msg []byte) ([]byte, error) {
	h := sha256.Sum256(msg)
	r, s, err := ecdsa.Sign(rand.Reader, priv, h[:])
	if err != nil {
		return nil, err
	}
	out := make([]byte, 64)
	r.FillBytes(out[:32])
	s.FillBytes(out[32:])
	return out, nil
}

// VerifyP1363 checks a 64 byte r||s signature over SHA-256(msg).
func VerifyP1363(pub *ecdsa.PublicKey, msg, sig []byte) bool {
	if len(sig) != 64 {
		return false
	}
	h := sha256.Sum256(msg)
	r := new(big.Int).SetBytes(sig[:32])
	s := new(big.Int).SetBytes(sig[32:])
	return ecdsa.Verify(pub, h[:], r, s)
}

// Fingerprint names an identity key: base64url(SHA-256(label || raw pub)).
func Fingerprint(idRaw []byte) string {
	h := sha256.New()
	h.Write([]byte(Label + " id"))
	h.Write([]byte{0})
	h.Write(idRaw)
	return B64.EncodeToString(h.Sum(nil))
}

// KID names a key exchange key: the first 8 bytes of SHA-256(raw pub).
func KID(kxRaw []byte) string {
	h := sha256.Sum256(kxRaw)
	return B64.EncodeToString(h[:8])
}

// KXCertMessage is the byte string the identity key signs to vouch for a key
// exchange public key between two unix times.
func KXCertMessage(kxRaw []byte, notBefore, notAfter uint64) []byte {
	m := make([]byte, 0, 64+len(kxRaw)+16)
	m = append(m, Label+" kx"...)
	m = append(m, 0)
	m = append(m, kxRaw...)
	m = binary.BigEndian.AppendUint64(m, notBefore)
	m = binary.BigEndian.AppendUint64(m, notAfter)
	return m
}

// RotationMessage is what an outgoing identity key signs to hand over to the
// next identity key.
func RotationMessage(prevRaw, nextRaw []byte, created uint64) []byte {
	m := make([]byte, 0, 64+len(prevRaw)+len(nextRaw)+8)
	m = append(m, Label+" rot"...)
	m = append(m, 0)
	m = append(m, prevRaw...)
	m = append(m, nextRaw...)
	m = binary.BigEndian.AppendUint64(m, created)
	return m
}

// Handshake -----------------------------------------------------------------

// TranscriptHash binds every public value of a handshake.
func TranscriptHash(idRaw, kxRaw, clientRaw, sid, serverNonce []byte) []byte {
	h := sha256.New()
	h.Write([]byte(Label + " hs"))
	h.Write([]byte{0})
	h.Write(idRaw)
	h.Write(kxRaw)
	h.Write(clientRaw)
	h.Write(sid)
	h.Write(serverNonce)
	return h.Sum(nil)
}

// MasterSecret = HKDF-SHA256(ikm = ECDH x coordinate, salt = transcript hash).
func MasterSecret(shared, th []byte) []byte {
	k, err := hkdf.Key(sha256.New, shared, th, Label+" ms", 32)
	if err != nil {
		panic(err)
	}
	return k
}

// Confirm proves possession of the master secret to the client.
func Confirm(ms, th []byte) []byte {
	ck, err := hkdf.Key(sha256.New, ms, nil, Label+" cf", 32)
	if err != nil {
		panic(err)
	}
	m := hmac.New(sha256.New, ck)
	m.Write(th)
	return m.Sum(nil)
}

// ServerHandshake runs the server half: it returns a fresh session id, server
// nonce, the master secret and the confirmation tag.
func ServerHandshake(kx *ecdh.PrivateKey, idRaw, clientRaw []byte) (sid, sn, ms, cf []byte, err error) {
	cpub, err := ecdh.P256().NewPublicKey(clientRaw)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("SEAL_HS_BAD_KEY: %w", err)
	}
	shared, err := kx.ECDH(cpub)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("SEAL_HS_BAD_KEY: %w", err)
	}
	sid = make([]byte, 16)
	sn = make([]byte, 32)
	rand.Read(sid)
	rand.Read(sn)
	th := TranscriptHash(idRaw, kx.PublicKey().Bytes(), clientRaw, sid, sn)
	ms = MasterSecret(shared, th)
	cf = Confirm(ms, th)
	return sid, sn, ms, cf, nil
}

// StreamKey derives the AES-256 key of one direction of one stream in one epoch.
func StreamKey(ms []byte, dir byte, stream uint64, epoch uint32) []byte {
	info := make([]byte, 0, 32)
	info = append(info, Label+" k"...)
	info = append(info, dir)
	info = binary.BigEndian.AppendUint64(info, stream)
	info = binary.BigEndian.AppendUint32(info, epoch)
	k, err := hkdf.Key(sha256.New, ms, nil, string(info), 32)
	if err != nil {
		panic(err)
	}
	return k
}

// Frame cipher ---------------------------------------------------------------

// Stream seals or opens the frames of ONE direction of ONE stream. Frames
// carry no sequence number: both sides count, so a dropped, duplicated or
// reordered frame fails authentication.
type Stream struct {
	ms     []byte
	sid    []byte
	dir    byte
	stream uint64
	seq    uint64
	epoch  uint32
	aead   cipher.AEAD
}

// NewStream prepares the cipher for one direction of a stream.
func NewStream(ms, sid []byte, dir byte, stream uint64) *Stream {
	s := &Stream{ms: ms, sid: sid, dir: dir, stream: stream}
	s.rekey(0)
	return s
}

func (s *Stream) rekey(epoch uint32) {
	block, err := aes.NewCipher(StreamKey(s.ms, s.dir, s.stream, epoch))
	if err != nil {
		panic(err)
	}
	g, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}
	s.aead = g
	s.epoch = epoch
}

func (s *Stream) prep() (nonce, aad []byte) {
	if e := uint32(s.seq >> EpochShift); e != s.epoch {
		s.rekey(e)
	}
	nonce = make([]byte, 12)
	binary.BigEndian.PutUint64(nonce[4:], s.seq)
	aad = make([]byte, 0, 64)
	aad = append(aad, Label...)
	aad = append(aad, s.sid...)
	aad = append(aad, s.dir)
	aad = binary.BigEndian.AppendUint64(aad, s.stream)
	aad = binary.BigEndian.AppendUint64(aad, s.seq)
	return nonce, aad
}

// Seq reports how many frames this stream has processed.
func (s *Stream) Seq() uint64 { return s.seq }

// Seal encrypts one frame: plaintext = type byte || payload.
func (s *Stream) Seal(typ byte, payload []byte) []byte {
	if len(payload) > MaxPayload {
		panic("sealcrypto: payload over MaxPayload")
	}
	nonce, aad := s.prep()
	pt := make([]byte, 1+len(payload), 1+len(payload)+16)
	pt[0] = typ
	copy(pt[1:], payload)
	s.seq++
	return s.aead.Seal(pt[:0], nonce, pt, aad)
}

// Open decrypts the next frame of the stream.
func (s *Stream) Open(ct []byte) (byte, []byte, error) {
	if len(ct) > MaxFrame {
		return 0, nil, ErrTooLarge
	}
	nonce, aad := s.prep()
	pt, err := s.aead.Open(nil, nonce, ct, aad)
	if err != nil {
		return 0, nil, ErrAuth
	}
	if len(pt) == 0 {
		return 0, nil, ErrEmpty
	}
	s.seq++
	return pt[0], pt[1:], nil
}

// Replay window --------------------------------------------------------------

// Window accepts each stream id at most once. Ids may arrive out of order (many
// HTTP requests in flight) but not older than Size below the highest seen.
type Window struct {
	max  uint64
	bits [WindowSize / 64]uint64
}

// WindowSize is how far behind the newest id an older id is still accepted.
const WindowSize = 4096

// Accept records id and reports whether it was fresh.
func (w *Window) Accept(id uint64) bool {
	if id == 0 {
		return false
	}
	if id > w.max {
		shift := id - w.max
		if shift >= WindowSize {
			w.bits = [WindowSize / 64]uint64{}
		} else {
			for i := uint64(0); i < shift; i++ {
				w.clear(w.max + 1 + i)
			}
		}
		w.max = id
		w.set(id)
		return true
	}
	if w.max-id >= WindowSize {
		return false
	}
	if w.get(id) {
		return false
	}
	w.set(id)
	return true
}

func (w *Window) set(id uint64)      { w.bits[(id%WindowSize)/64] |= 1 << (id % 64) }
func (w *Window) clear(id uint64)    { w.bits[(id%WindowSize)/64] &^= 1 << (id % 64) }
func (w *Window) get(id uint64) bool { return w.bits[(id%WindowSize)/64]&(1<<(id%64)) != 0 }
