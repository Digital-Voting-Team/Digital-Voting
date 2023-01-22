package block

type Witness struct {
	ValidatorsPublicKeys [][33]byte `json:"public_keys"`
	ValidatorsSignatures [][33]byte `json:"signatures"`
}

func (w *Witness) addSignature(publicKey, signature [33]byte) {
	w.ValidatorsPublicKeys = append(w.ValidatorsSignatures, publicKey)
	w.ValidatorsSignatures = append(w.ValidatorsSignatures, signature)
}
