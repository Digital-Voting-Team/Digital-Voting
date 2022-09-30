package keys

import (
	"crypto/ed25519"
	"digital-voting/strkey"
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

// Verify checks whether message was signed by kp's keys.
func (kp *FromAddress) Verify(message []byte, sig []byte) error {
	if len(sig) != 64 {
		return ErrInvalidSignature
	}
	if !ed25519.Verify(kp.PublicKey()[:], message, sig) {
		return ErrInvalidSignature
	}
	return nil
}

// Sign method returns error because this KP cannot sign messages.
func (kp *FromAddress) Sign(_ []byte) ([]byte, error) {
	return nil, ErrCannotSign
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
