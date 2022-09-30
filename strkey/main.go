package strkey

import (
	"encoding/base32"
	"errors"
	"fmt"
)

// ErrInvalidVersionByte is returned when the version byte from a provided
// strkey-encoded string is not one of the valid values.
var ErrInvalidVersionByte = errors.New("invalid version byte")

// VersionByte represents one of the possible prefix values for a StrKey base
// string--the string when encoded using base32 yields a final StrKey.
type VersionByte byte

const (
	//VersionByteAccountID is the version byte used for encoded stellar addresses
	VersionByteAccountID VersionByte = 6 << 3 // Base32-encodes to 'G...'

	//VersionByteSeed is the version byte used for encoded stellar seed
	VersionByteSeed = 18 << 3 // Base32-encodes to 'S...'
)

// maxPayloadSize is the maximum length of the payload for all versions. The
// largest strkey is a signed payload: 32-byte public key + 4-byte payload
// length + 64-byte payload
const maxPayloadSize = 100

// maxRawSize is the maximum length of a strkey in its raw form not encoded.
const maxRawSize = 1 + /* version byte */ maxPayloadSize

// maxEncodedSize is the maximum length of a strkey when base32 encoded.
const maxEncodedSize = (maxRawSize*8 + 4) / 5 // (8n+4)/5 is the EncodedLen for no padding

// encoding to use when encoding and decoding a strkey to and from strings.
var encoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// Decode decodes the provided StrKey into a raw value, checking the checksum
// and ensuring the expected VersionByte (the version parameter) is the value
// actually encoded into the provided src string.
func Decode(expected VersionByte, src string) ([]byte, error) {
	if err := checkValidVersionByte(expected); err != nil {
		return nil, err
	}

	raw, err := base32.StdEncoding.WithPadding(base32.StdPadding).DecodeString(src)
	if err != nil {
		return nil, err
	}

	if len(raw) < 3 {
		return nil, errors.New("decoded string is too short")
	}

	// decode into components
	version := VersionByte(raw[0])
	payload := raw[1:]

	if version != expected {
		return nil, ErrInvalidVersionByte
	}

	return payload, nil
}

// MustDecode is like Decode, but panics on error
func MustDecode(expected VersionByte, src string) []byte {
	d, err := Decode(expected, src)
	if err != nil {
		panic(err)
	}
	return d
}

// Encode encodes the provided data to a StrKey, using the provided version
// byte.
func Encode(version VersionByte, src []byte) (string, error) {
	if err := checkValidVersionByte(version); err != nil {
		return "", err
	}

	payloadSize := len(src)

	// check src does not exceed maximum payload size
	if payloadSize > maxPayloadSize {
		return "", fmt.Errorf("data exceeds maximum payload size for strkey")
	}

	rawArr := [maxRawSize]byte{}
	rawSize := 1 + payloadSize
	raw := rawArr[:rawSize]
	raw[0] = byte(version)
	copy(raw[1:], src)

	// base32 encode
	encArr := [maxEncodedSize]byte{}
	encSize := encoding.WithPadding(base32.StdPadding).EncodedLen(rawSize)
	enc := encArr[:encSize]
	encoding.WithPadding(base32.StdPadding).Encode(enc, raw)

	return string(enc), nil
}

// MustEncode is like Encode, but panics on error.
func MustEncode(version VersionByte, src []byte) string {
	e, err := Encode(version, src)
	if err != nil {
		panic(err)
	}
	return e
}

// checkValidVersionByte returns an error if the provided value
// is not one of the defined valid version byte constants.
func checkValidVersionByte(version VersionByte) error {
	switch version {
	case VersionByteAccountID, VersionByteSeed:
		return nil
	default:
		return ErrInvalidVersionByte
	}
}
