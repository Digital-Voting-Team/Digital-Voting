package block

import (
	"digital-voting/signature/keys"
	signature "digital-voting/signature/signatures/single_signature"
)

type Witness struct {
	ValidatorsPublicKeys []keys.PublicKeyBytes            `json:"public_keys"`
	ValidatorsSignatures []signature.SingleSignatureBytes `json:"signatures"`
}

func (w *Witness) addSignature(publicKey keys.PublicKeyBytes, signature signature.SingleSignatureBytes) {
	w.ValidatorsPublicKeys = append(w.ValidatorsPublicKeys, publicKey)
	w.ValidatorsSignatures = append(w.ValidatorsSignatures, signature)
}
