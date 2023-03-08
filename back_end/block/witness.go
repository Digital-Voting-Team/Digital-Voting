package block

type Witness struct {
	ValidatorsPublicKeys [][33]byte `json:"public_keys"`
	ValidatorsSignatures [][65]byte `json:"signatures"`
}

func (w *Witness) addSignature(publicKey [33]byte, signature [65]byte) {
	w.ValidatorsPublicKeys = append(w.ValidatorsPublicKeys, publicKey)
	w.ValidatorsSignatures = append(w.ValidatorsSignatures, signature)
}
