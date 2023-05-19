package block

import (
	"digital-voting/identity_provider"
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

func (w *Witness) Verify(provider *identity_provider.IdentityProvider, message string) bool {
	if len(w.ValidatorsPublicKeys) != len(w.ValidatorsSignatures) {
		return false
	}

	for i, publicKey := range w.ValidatorsPublicKeys {
		if !provider.CheckPubKeyPresence(publicKey, identity_provider.Validator) {
			return false
		}

		if !signature.NewECDSA().VerifyBytes(message, publicKey, w.ValidatorsSignatures[i]) {
			return false
		}
	}

	return true
}
