package elliptic

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
)

// ErrPrivateKeyMissing is returned when the PrivateKey is nil
var ErrPrivateKeyMissing = errors.New("no PrivateKey")

// ErrInvalidCurve is returned by NewPrivateKey if a non-standard curve is supplied
var ErrInvalidCurve = errors.New("invalid curve")

// PrivateKeyIDLength is the length of the PrivateKeyID
const PrivateKeyIDLength = 32

// PrivateKeyID is an array type holding unique identifiers for PrivateKeys
type PrivateKeyID [PrivateKeyIDLength]byte

// NewPrivateKey returns a new PrivateKey against the specified ecdh.Curve
// which must be one of P224, P256, P384, P521
func NewPrivateKey(curve Curve) (*PrivateKey, error) {
	if curve == nil {
		return nil, ErrInvalidCurve
	}
	return curve.GenerateKey()
}

// PrivateKey abstracts specific key implementation
type PrivateKey struct {
	c  Curve
	k  *ecdsa.PrivateKey
	id PrivateKeyID
}

func (p *PrivateKey) createID() error {
	// Make ID() non-deterministic
	b := make([]byte, PrivateKeyIDLength)
	rand.Read(b)
	copy(p.id[:], b)
	return nil
}

// ID is the unique identifier of this private key
func (p *PrivateKey) ID() PrivateKeyID {
	var id PrivateKeyID
	copy(id[:], p.id[:])
	return id
}

// Curve used to create the private key
func (p *PrivateKey) Curve() Curve {
	return p.c
}

// PublicKey returns the abstracted public key of this PrivateKey instance
func (p *PrivateKey) PublicKey() *PublicKey {
	return &PublicKey{
		c: p.c,
		k: &p.k.PublicKey,
	}
}

// Marshal encodes the PrivateKey to a JSON []byte
func (p *PrivateKey) Marshal() ([]byte, error) {
	b, err := x509.MarshalPKCS8PrivateKey(p.k)
	if err != nil {
		return nil, err
	}
	m := &privateKey{
		ID:  base64.RawStdEncoding.EncodeToString(p.id[:]),
		Key: base64.RawStdEncoding.EncodeToString(b),
	}
	return json.Marshal(m)
}

// UnMarshalPrivateKey decodes a PrivateKey from a JSON []byte
func UnMarshalPrivateKey(data []byte) (*PrivateKey, error) {

	var m privateKey
	err := json.Unmarshal(data, &m)
	if err != nil {
		return nil, err
	}

	der, err := base64.RawStdEncoding.DecodeString(m.Key)
	if err != nil {
		return nil, err
	}
	id, err := base64.RawStdEncoding.DecodeString(m.ID)
	if err != nil {
		return nil, err
	}

	k, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, err
	}

	key, ok := k.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("invalid der")
	}

	c, err := findCurve(key.Curve)
	if err != nil {
		return nil, err
	}

	p := &PrivateKey{k: key, c: c}
	copy(p.id[:], id)

	return p, nil
}

type privateKey struct {
	ID  string `json:"i"`
	Key string `json:"k"`
}

// Sign will hash the provided data and then generate a signature based on the hash
// The signature is encoded as base64 []byte
func (p *PrivateKey) Sign(data []byte) ([]byte, error) {
	hash := sha256.New()
	hash.Write([]byte(data))
	h := hash.Sum(nil)

	b, err := ecdsa.SignASN1(rand.Reader, p.k, h)
	if err != nil {
		return nil, err
	}
	return []byte(base64.RawStdEncoding.EncodeToString(b)), nil
}

// PublicKey abstracts specific key implementation
type PublicKey struct {
	c Curve
	k *ecdsa.PublicKey
}

// Curve used to create this PublicKey
func (p *PublicKey) Curve() Curve {
	return p.c
}

// Marshal encodes the PublicKey to a base64 []byte
func (p *PublicKey) Marshal() ([]byte, error) {
	b, err := x509.MarshalPKIXPublicKey(p.k)
	if err != nil {
		return nil, err
	}
	return []byte(base64.RawStdEncoding.EncodeToString(b)), nil
}

// UnMarshalPublicKey decodes a PublicKey from a base64 []byte
func UnMarshalPublicKey(b64der []byte) (*PublicKey, error) {
	der, err := base64.RawStdEncoding.DecodeString(string(b64der))
	if err != nil {
		return nil, err
	}

	k, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, err
	}

	key, ok := k.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("invalid der")
	}

	c, err := findCurve(key.Curve)
	if err != nil {
		return nil, err
	}

	return &PublicKey{k: key, c: c}, nil
}

// Verify will hash the provided data and verify the provided signature,
// which should be encoded as base64, using the PublicKey
func (p *PublicKey) Verify(signature, data []byte) (bool, error) {
	b, err := base64.RawStdEncoding.DecodeString(string(signature))
	if err != nil {
		return false, err
	}

	hash := sha256.New()
	hash.Write([]byte(data))
	h := hash.Sum(nil)

	return ecdsa.VerifyASN1(p.k, h, b), nil
}

// NewSharedSecret creates a new one-time local key pair using the remotely specified Curve, to create a secret
func NewSharedSecret(remotePubKey *PublicKey) (*PrivateKey, []byte, error) {

	if remotePubKey == nil {
		return nil, nil, ErrPublicKeyMissing
	}

	newPrivKey, err := NewPrivateKey(remotePubKey.Curve())
	if err != nil {
		return nil, nil, err
	}

	newPrivECDHKey, err := newPrivKey.k.ECDH()
	if err != nil {
		return nil, nil, err
	}

	remotePubECDHKey, err := remotePubKey.k.ECDH()
	if err != nil {
		return nil, nil, err
	}

	sharedSecret, err := newPrivECDHKey.ECDH(remotePubECDHKey)
	if err != nil {
		return nil, nil, err
	}
	// sha256 hash the secret to ensure it is 2*aes.BlockSize in length
	h := sha256.Sum256(sharedSecret)

	return newPrivKey, h[:], nil
}

// ErrPublicKeyMissing returned if the PublicKey is nil
var ErrPublicKeyMissing = errors.New("missing public key")

// RecreateSharedSecret is used by the remote party, having received the one-time public key, to create the same secret
func RecreateSharedSecret(privKey *PrivateKey, remotePubKey *PublicKey) ([]byte, error) {

	if privKey == nil {
		return nil, ErrPrivateKeyMissing
	}
	if remotePubKey == nil {
		return nil, ErrPublicKeyMissing
	}

	privECDHKey, err := privKey.k.ECDH()
	if err != nil {
		return nil, err
	}

	remotePubECDHKey, err := remotePubKey.k.ECDH()
	if err != nil {
		return nil, err
	}

	sharedSecret, err := privECDHKey.ECDH(remotePubECDHKey)
	if err != nil {
		return nil, err
	}
	// sha256 hash the secret to ensure it is 2*aes.BlockSize in length
	h := sha256.Sum256(sharedSecret)

	return h[:], nil
}
