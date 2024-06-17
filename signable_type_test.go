package elliptic

import (
	"bytes"
	"encoding/json"
	"fmt"
)

type Address struct {
	HouseNo  int    `json:"no"`
	Street   string `json:"street"`
	PostCode string `json:"postcode"`
}

func (a *Address) Collect() []byte {
	return nil
}

func (a *Address) Marshal() ([]byte, error) {
	return json.Marshal(a)
}

func (a *Address) UnMarshal(data []byte) error {
	return json.Unmarshal(data, a)
}

func (a *Address) New() any {
	return &Address{}
}

func ExampleNewSigned() {

	var privateKeyID PrivateKeyID
	var publicKey *PublicKey
	var signedObj *Signed[*Address]

	{
		c, _ := NewCurve(CurveP256)
		privateKey, _ := c.GenerateKey()
		publicKey = privateKey.PublicKey()
		copy(privateKeyID[:], privateKeyID[:])

		signedObj, _ = NewSigned(privateKey, &Address{
			HouseNo:  10,
			Street:   "Downing Street",
			PostCode: "",
		})
	}

	ok, _ := signedObj.Verify(publicKey)
	fmt.Println(ok)
	fmt.Println(!bytes.Equal(privateKeyID[:], signedObj.ID[:]))

	// Output: true
	// true
}
