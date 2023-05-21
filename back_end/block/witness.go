package block

import (
	"digital-voting/node/account_manager"
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

func (w *Witness) Verify(accountManager *account_manager.AccountManager, message string) bool {
	if len(w.ValidatorsPublicKeys) == 0 {
		return false
	}

	if len(w.ValidatorsPublicKeys) != len(w.ValidatorsSignatures) {
		return false
	}

	for i, publicKey := range w.ValidatorsPublicKeys {
		if !accountManager.CheckPubKeyPresence(publicKey, account_manager.Validator) {
			return false
		}

		if !signature.NewECDSA().VerifyBytes(message, publicKey, w.ValidatorsSignatures[i]) {
			return false
		}
	}

	return true
}
