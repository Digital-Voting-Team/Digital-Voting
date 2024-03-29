package transaction_specific

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/Digital-Voting-Team/Digital-Voting/pkg/signature/keys"
	"github.com/Digital-Voting-Team/Digital-Voting/pkg/validator/repository"
	"github.com/Digital-Voting-Team/Digital-Voting/pkg/validator/repository/account_manager"
	"github.com/Digital-Voting-Team/Digital-Voting/pkg/validator/repository/indexed_groups"
)

type TxGroupCreation struct {
	GroupIdentifier   [33]byte              `json:"group_identifier"`
	GroupName         [256]byte             `json:"group_name"`
	MembersPublicKeys []keys.PublicKeyBytes `json:"members_public_keys"`
}

func NewTxGroupCreation(groupName string, membersPublicKeys []keys.PublicKeyBytes) *TxGroupCreation {
	grpName := [256]byte{}
	copy(grpName[:], groupName)

	hasher := sha256.New()

	groupIdentifier := []byte(fmt.Sprintf("%v%v", grpName, membersPublicKeys))
	hasher.Write(groupIdentifier)
	groupIdentifier = hasher.Sum(nil)
	grpId := [33]byte{}
	//version byte
	//grpId[0] = 0
	copy(grpId[1:], groupIdentifier)

	return &TxGroupCreation{GroupIdentifier: grpId, GroupName: grpName, MembersPublicKeys: membersPublicKeys}
}

func (tx *TxGroupCreation) AddGroupMember(publicKey keys.PublicKeyBytes) {
	tx.MembersPublicKeys = append(tx.MembersPublicKeys, publicKey)
}

func (tx *TxGroupCreation) RemoveGroupMember(publicKey keys.PublicKeyBytes) {
	for i, key := range tx.MembersPublicKeys {
		//it works for [33]byte
		if key == publicKey {
			tx.MembersPublicKeys = append(tx.MembersPublicKeys[:i], tx.MembersPublicKeys[i+1:]...)
			return
		}
	}
}

func (tx *TxGroupCreation) GetSignatureMessage() string {
	return fmt.Sprint(tx.GroupIdentifier, tx.GroupName, tx.MembersPublicKeys)
}

func (tx *TxGroupCreation) String() string {
	str, _ := json.Marshal(tx)
	return string(str)
}

func (tx *TxGroupCreation) GetHashString() string {
	hash := tx.GetHash()

	return base64.URLEncoding.EncodeToString(hash[:])
}

func (tx *TxGroupCreation) GetHash() [32]byte {
	hasher := sha256.New()

	bytes := []byte(tx.GetSignatureMessage())
	hasher.Write(bytes)
	bytes = hasher.Sum(nil)

	hasher.Reset()
	hasher.Write(bytes)

	hash := [32]byte{}
	copy(hash[:], hasher.Sum(nil)[:32])

	return hash
}

func (tx *TxGroupCreation) IsEqual(otherTransaction *TxGroupCreation) bool {
	return tx.GetHash() == otherTransaction.GetHash()
}

func (tx *TxGroupCreation) CheckPublicKeyByRole(indexedData *repository.IndexedData, publicKey keys.PublicKeyBytes) bool {
	return indexedData.AccountManager.CheckPubKeyPresence(publicKey, account_manager.RegistrationAdmin)
}

func (tx *TxGroupCreation) checkData(indexedData *repository.IndexedData) bool {
	for _, pubKey := range tx.MembersPublicKeys {
		if !indexedData.AccountManager.CheckPubKeyPresence(pubKey, account_manager.User) {
			return false
		}
	}

	return len(tx.MembersPublicKeys) > 0 && tx.GroupIdentifier != [33]byte{} && tx.GroupName != [256]byte{}
}

func (tx *TxGroupCreation) CheckOnCreate(indexedData *repository.IndexedData, publicKey keys.PublicKeyBytes) bool {
	if indexedData.AccountManager.CheckPubKeyPresence(tx.GroupIdentifier, account_manager.GroupIdentifier) {
		return false
	}

	return tx.checkData(indexedData) && tx.CheckPublicKeyByRole(indexedData, publicKey)
}

func (tx *TxGroupCreation) Verify(indexedData *repository.IndexedData, publicKey keys.PublicKeyBytes) bool {
	return tx.checkData(indexedData) && tx.CheckPublicKeyByRole(indexedData, publicKey)
}

func (tx *TxGroupCreation) ActualizeIndexedData(indexedData *repository.IndexedData) {
	indexedData.AccountManager.AddPubKey(tx.GroupIdentifier, account_manager.GroupIdentifier)
	indexedData.GroupManager.AddNewGroup(indexed_groups.GroupDTO{
		GroupIdentifier:   tx.GroupIdentifier,
		GroupName:         tx.GroupName,
		MembersPublicKeys: tx.MembersPublicKeys,
	})
}
