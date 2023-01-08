package ecc

import (
	"math/big"
	"strings"
)

func Hex2int(hexStr string) *big.Int {
	// remove 0x suffix if found in the input string
	cleaned := strings.Replace(hexStr, "0x", "", -1)

	// base 16 for hexadecimal
	n := new(big.Int)
	n.SetString(cleaned, 16)
	return n
}

func GetInt(val int64) *big.Int {
	return new(big.Int).SetInt64(val)
}

func CheckInterval(val, min, max *big.Int) bool {
	if new(big.Int).Sub(val, min).Sign() < 0 {
		return false
	}

	if new(big.Int).Sub(max, val).Sign() < 0 {
		return false
	}

	return true
}

func Clone(int2 *big.Int) *big.Int {
	return new(big.Int).Set(int2)
}
