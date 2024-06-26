elliptic
========

[![Go Doc](https://pkg.go.dev/badge/github.com/secure-conversation/elliptic.svg)](https://pkg.go.dev/github.com/secure-conversation/elliptic)
[![Go Report Card](https://goreportcard.com/badge/github.com/secure-conversation/elliptic)](https://goreportcard.com/report/github.com/secure-conversation/elliptic)

Provides Elliptic Curve based asymmetric encryption and signing.

In particular, shared secrets are straightforward to generate using Elliptic Curve Diffie-Hellman [ECDH](https://en.wikipedia.org/wiki/Elliptic-curve_Diffie%E2%80%93Hellman) using `NewSharedSecret` and `RecreateSharedSecret`.

Each party creates a `PrivateKey` using a `Curve` of their choice, then makes their `PublicKey` generally available.  `NewSharedSecret` uses the `PublicKey` of the remote party and a one-time `PrivateKey` to create a shared secret, returning both the one-time key details and the shared secret.  

Passing the corresponding one-time `PublicKey` allows the remote `PrivateKey` owner to also generate the shared secret, which can therefore be used as a symmetric encryption key.

Keys wrap their `ecdsa` equivalents, to add serialisation and simplify signing.  Each `PrivateKey` additionally has a unique `ID` value.

`Signed[T Signable]` is a generic type, constrained by `Signable`, that holds data and its signature, as generated by a `PrivateKey`.  `Signed` stores the `ID` of the signing `PrivateKey` allowing simpler `PublicKey` retrieval for verification of the signed data by other parties.

`Signed` supports serialisation to JSON, using base64 raw std encoding.

Example:

```go
package main

import "github.com/secure-conversation/elliptic"

// Address must implement Signable (not shown)
type Address struct {}

func main() {

  // Unmarshal private key providing identity 
  b := []byte("...")
  privateKey, _ := elliptic.UnMarshalPrivateKey(b)
  
  // Sign data as originating from this identity,
  // and providing certainty of non-tampering
  signedObj, _ = elliptic.NewSigned(privateKey, &Address{
    HouseNo:  10,
    Street:   "Downing Street",
    PostCode: "SW1A 2AB",
  })

  // ... send the signedObj somewhere, who can verify
  // source identity and non-tampered nature of data

}
```

Note that `Collectable.Collect()` must ensure that all attributes of the `Signable` type are reliably (i.e. consistently) converted to the same `[]byte` slice, otherwise signature verification may fail.
