package strkey

import (
	"encoding/base32"
	"errors"
	"fmt"
)

var ErrInvalidVersionByte = errors.New("invalid version byte")

type VersionByte byte

const (
	//VersionBytePublicKey is the version byte used for encoded public keys
	VersionBytePublicKey VersionByte = 6 << 3 // Base32-encodes to 'G...'

	//VersionByteSeed is the version byte used for encoded seeds
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

func checkValidVersionByte(version VersionByte) error {
	switch version {
	case VersionBytePublicKey, VersionByteSeed:
		return nil
	default:
		return ErrInvalidVersionByte
	}
}
