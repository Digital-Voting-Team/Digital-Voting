package block

import (
	"github.com/Digital-Voting-Team/Digital-Voting/pkg/signature/keys"
	ss "github.com/Digital-Voting-Team/Digital-Voting/pkg/signature/signatures/single_signature"
	"github.com/Digital-Voting-Team/Digital-Voting/pkg/validator/repository/account_manager"
	"log"
)

type Witness struct {
	ValidatorsPublicKeys []keys.PublicKeyBytes     `json:"public_keys"`
	ValidatorsSignatures []ss.SingleSignatureBytes `json:"signatures"`
}

func (w *Witness) addSignature(publicKey keys.PublicKeyBytes, signature ss.SingleSignatureBytes) {
	w.ValidatorsPublicKeys = append(w.ValidatorsPublicKeys, publicKey)
	w.ValidatorsSignatures = append(w.ValidatorsSignatures, signature)
}

func (w *Witness) Verify(accountManager *account_manager.AccountManager, message string) bool {
	if len(w.ValidatorsPublicKeys) == 0 {
		log.Println("Witness is empty")
		return false
	}

	if len(w.ValidatorsPublicKeys) != len(w.ValidatorsSignatures) {
		log.Println("Witness is corrupted")
		return false
	}

	for i, publicKey := range w.ValidatorsPublicKeys {
		if !accountManager.CheckPubKeyPresence(publicKey, account_manager.Validator) {
			log.Println("Witness contains invalid public key")
			return false
		}

		if !ss.NewECDSA().VerifyEdDSABytes(message, publicKey, w.ValidatorsSignatures[i]) {
			log.Println("Witness contains invalid signature")
			return false
		}
	}

	return true
}
