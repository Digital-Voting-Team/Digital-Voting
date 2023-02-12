package keys

import (
	"digital-voting/curve"
	"digital-voting/strkey"
	"math/big"
)

// FromAddress represents a keys to which only the address is known. This KP
// can verify signatures, but cannot sign messages.
type FromAddress struct {
	address string
}

// Address is address getter.
func (kp *FromAddress) Address() string {
	return kp.address
}

// PublicKey is public key getter.
func (kp *FromAddress) PublicKey() *[32]byte {
	bytes := strkey.MustDecode(strkey.VersionByteAccountID, kp.address)
	var result [32]byte

	copy(result[:], bytes)

	return &result
}

// FromAddress gets the address-only representation of these
// keys, which is itself.
func (kp *FromAddress) FromAddress() (*FromAddress, error) {
	return kp, nil
}

// Hint provides four last bytes of public key.
func (kp *FromAddress) Hint() (r [4]byte) {
	copy(r[:], kp.PublicKey()[28:])
	return
}

// Equal compares two FromAddress instances.
func (kp *FromAddress) Equal(a *FromAddress) bool {
	if kp == nil && a == nil {
		return true
	}
	if kp == nil || a == nil {
		return false
	}
	return kp.address == a.address
}

func newFromAddress(address string) (*FromAddress, error) {
	if _, err := strkey.Decode(strkey.VersionByteAccountID, address); err != nil {
		return nil, ErrInvalidKey
	}

	return &FromAddress{
		address: address,
	}, nil
}

func (kp *FromAddress) GetPrivateKey() *big.Int {
	return nil
}

func (kp *FromAddress) GetPublicKey() *curve.Point {
	return nil
}

func (kp *FromAddress) GetKeyImage() *curve.Point {
	return nil
}
