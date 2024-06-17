package elliptic

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
)

// CurveType describes the supported Elliptic Curves
type CurveType int

func (c CurveType) String() string {
	switch c {
	case CurveP224:
		return curve224
	case CurveP256:
		return curve256
	case CurveP384:
		return curve384
	case CurveP521:
		return curve521
	}
	panic("unknown CurveType")
}

const (
	CurveP224 CurveType = iota
	CurveP256
	CurveP384
	CurveP521
)

const (
	curve224 = "P224"
	curve256 = "P256"
	curve384 = "P384"
	curve521 = "P521"
)

// Curve represents an Elliptic Curve of some sort
type Curve interface {
	Type() CurveType
	GenerateKey() (*PrivateKey, error)
}

type crv struct {
	t CurveType
	c elliptic.Curve
}

// Type returns the CurveType of this instance
func (c *crv) Type() CurveType {
	return c.t
}

// GenerateKey returns a new PrivateKey based on this instance's CurveType
func (c *crv) GenerateKey() (*PrivateKey, error) {
	key, err := ecdsa.GenerateKey(c.c, rand.Reader)
	if err != nil {
		return nil, err
	}
	p := &PrivateKey{k: key, c: c}
	err = p.createID()
	if err != nil {
		return nil, err
	}
	return p, nil
}

// ErrUnknownCurveType returned when an unsupported Elliptic Curve is specified
var ErrUnknownCurveType = errors.New("unknown elliptic curve type")

// NewCurve returns an instance of Curve of the specified type
func NewCurve(t CurveType) (Curve, error) {
	switch t {
	case CurveP224:
		return &crv{
			c: elliptic.P224(),
			t: t,
		}, nil
	case CurveP256:
		return &crv{
			c: elliptic.P256(),
			t: t,
		}, nil
	case CurveP384:
		return &crv{
			c: elliptic.P384(),
			t: t,
		}, nil
	case CurveP521:
		return &crv{
			c: elliptic.P384(),
			t: t,
		}, nil
	}
	return nil, ErrUnknownCurveType
}

// ParseCurve creates a Curve from the stringised CurveType
func ParseCurve(typ string) (Curve, error) {
	switch typ {
	case curve224:
		return NewCurve(CurveP224)
	case curve256:
		return NewCurve(CurveP256)
	case curve384:
		return NewCurve(CurveP384)
	case curve521:
		return NewCurve(CurveP521)
	}
	return nil, ErrInvalidCurve
}

// findCurve returns the Curve for the specified elliptic.Curve
func findCurve(c elliptic.Curve) (Curve, error) {
	switch c {
	case elliptic.P224():
		return p224, nil
	case elliptic.P256():
		return p256, nil
	case elliptic.P384():
		return p384, nil
	case elliptic.P521():
		return p521, nil
	default:
		return nil, ErrInvalidCurve
	}
}

// Since elliptic.Curve are const, can make singletons
var p224 Curve = &crv{c: elliptic.P224(), t: CurveP224}
var p256 Curve = &crv{c: elliptic.P256(), t: CurveP256}
var p384 Curve = &crv{c: elliptic.P384(), t: CurveP384}
var p521 Curve = &crv{c: elliptic.P521(), t: CurveP521}
