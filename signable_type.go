package elliptic

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
)

// Collectable returns a invariant []byte representation of an instance
type Collectable interface {
	Collect() []byte
}

// Marshallable must be implemented by types that can be Signed
type Marshallable interface {
	Marshal() ([]byte, error)
	UnMarshal(data []byte) error
}

// Signable are types that can marshal themselves, collect themselevs, and create new instances of themselves
type Signable interface {
	Marshallable
	Collectable
	New() any
}

// NewSigned creates a new instance of Signed, signed using the privKey.
// The ID is the identifier of the privKey used to create the signature.
// Both the data and the ID are included in the signature.
func NewSigned[T Signable](privKey *PrivateKey, data T) (*Signed[T], error) {
	s := &Signed[T]{
		Data: data,
		ID:   privKey.ID(),
	}

	m, err := s.signingMaterial()
	if err != nil {
		return nil, err
	}
	sign, err := privKey.Sign(m)
	if err != nil {
		return nil, err
	}

	s.signature = sign
	return s, nil
}

// Signed creates a hidden signature which can be used to verify the contents are untampered,
// and/or to confirm the private key used to generate the signature
type Signed[T Signable] struct {
	signature []byte
	ID        PrivateKeyID
	Data      T
}

// Verify confirms that the content of the instance has not be tampered, and corresponds
// to the signature generated using the privKey of the specified pubKey.
// With the Handshake protocol, the pubKey should be associated to the ID attribute of the instance.
func (s *Signed[T]) Verify(pubKey *PublicKey) (bool, error) {

	data, err := s.signingMaterial()
	if err != nil {
		return false, err
	}

	return pubKey.Verify(s.signature, data)
}

func SigningMaterialSpacer() []byte {
	return []byte("|")
}

func (s *Signed[T]) signingMaterial() ([]byte, error) {
	hash := sha256.New()
	hash.Write(s.Data.Collect())
	hash.Write(SigningMaterialSpacer())
	hash.Write(s.ID[:])
	return hash.Sum(SigningMaterialSpacer()), nil
}

// Marshal encodes the instance to a JSON []byte
func (s *Signed[T]) Marshal() ([]byte, error) {

	data, err := s.Data.Marshal()
	if err != nil {
		return nil, err
	}

	bb := &signedJSON{
		Signature: base64.RawStdEncoding.EncodeToString(s.signature),
		ID:        base64.RawStdEncoding.EncodeToString(s.ID[:]),
		Data:      base64.RawStdEncoding.EncodeToString(data),
	}

	return json.Marshal(bb)
}

type signedJSON struct {
	Signature string `json:"s"`
	ID        string `json:"i"`
	Data      string `json:"d"`
}

// ParseSigned decodes the JSON []byte into an unverified Signed instance
func ParseSigned[T Signable](b []byte) (*Signed[T], error) {
	var s signedJSON
	err := json.Unmarshal(b, &s)
	if err != nil {
		return nil, err
	}
	sig, err := base64.RawStdEncoding.DecodeString(s.Signature)
	if err != nil {
		return nil, err
	}
	id, err := base64.RawStdEncoding.DecodeString(s.ID)
	if err != nil {
		return nil, err
	}
	data, err := base64.RawStdEncoding.DecodeString(s.Data)
	if err != nil {
		return nil, err
	}

	var t T
	t = t.New().(T)
	err = t.UnMarshal(data)
	if err != nil {
		return nil, err
	}

	st := &Signed[T]{
		signature: sig,
		Data:      t,
	}
	copy(st.ID[:], id)

	return st, nil
}
