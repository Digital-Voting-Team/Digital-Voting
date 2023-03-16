package validation

import (
	"digital-voting/identity_provider"
	ringSignature "digital-voting/signature/signatures/ring_signature"
	signatures "digital-voting/signature/signatures/single_signature"
	"digital-voting/transaction"
	"digital-voting/transaction/transaction_specific"
)

const (
	AccountCreation uint8 = iota
	GroupCreation
	VotingCreation
	Vote
	VoteAnonymous
)

func ValidateTransaction(tx transaction.ITransaction, identityProvider *identity_provider.IdentityProvider) bool {
	// TODO: think of how to actually get data from Identity Provider
	ecdsa := signatures.NewECDSA()

	if tx.GetTxType() == VoteAnonymous {
		return validateVoteAnonymous(*(tx.(*transaction_specific.TxVoteAnonymous)), identityProvider)
	}

	genTx := *(tx.(*transaction.Transaction))
	txBody := genTx.TxBody
	check := true

	switch genTx.GetTxType() {
	case AccountCreation:
		check = validateAccountCreation(*(txBody.(*transaction_specific.TxAccountCreation)), identityProvider) &&
			identityProvider.CheckPubKeyPresence(
				genTx.PublicKey,
				identity_provider.RegistrationAdmin,
			)
	case GroupCreation:
		check = validateGroupCreation(*(txBody.(*transaction_specific.TxGroupCreation)), identityProvider) &&
			identityProvider.CheckPubKeyPresence(
				genTx.PublicKey,
				identity_provider.RegistrationAdmin,
			)
	case VotingCreation:
		check = validateVotingCreation(*(txBody.(*transaction_specific.TxVotingCreation)), identityProvider) &&
			identityProvider.CheckPubKeyPresence(
				genTx.PublicKey,
				identity_provider.VotingCreationAdmin,
			)
	case Vote:
		check = validateVote(*(txBody.(*transaction_specific.TxVote))) &&
			identityProvider.CheckPubKeyPresence(
				genTx.PublicKey,
				identity_provider.User,
			)
	default:
		return false
	}

	return check &&
		ecdsa.VerifyBytes(
			genTx.GetHash(),
			genTx.PublicKey,
			genTx.Signature,
		)
}

func validateVoteAnonymous(transaction transaction_specific.TxVoteAnonymous, identityProvider *identity_provider.IdentityProvider) bool {
	// TODO: add a way of getting voting by its link to check connected data
	for _, pubKey := range transaction.PublicKeys {
		if !identityProvider.CheckPubKeyPresence(pubKey, identity_provider.User) {
			return false
		}
	}

	ecdsaRs := ringSignature.NewECDSA_RS()
	return ecdsaRs.VerifyBytes(transaction.GetHash(), transaction.PublicKeys, transaction.RingSignature, transaction.KeyImage)
}

func validateAccountCreation(transaction transaction_specific.TxAccountCreation, identityProvider *identity_provider.IdentityProvider) bool {
	// TODO: think of a better way to check
	return !identityProvider.CheckPubKeyPresence(transaction.NewPublicKey, identity_provider.User) &&
		!identityProvider.CheckPubKeyPresence(transaction.NewPublicKey, identity_provider.RegistrationAdmin) &&
		!identityProvider.CheckPubKeyPresence(transaction.NewPublicKey, identity_provider.VotingCreationAdmin) &&
		!identityProvider.CheckPubKeyPresence(transaction.NewPublicKey, identity_provider.GroupIdentifier)
}

func validateGroupCreation(transaction transaction_specific.TxGroupCreation, identityProvider *identity_provider.IdentityProvider) bool {
	if identityProvider.CheckPubKeyPresence(transaction.GroupIdentifier, identity_provider.GroupIdentifier) {
		return false
	}
	for _, pubKey := range transaction.MembersPublicKeys {
		if !identityProvider.CheckPubKeyPresence(pubKey, identity_provider.User) {
			return false
		}
	}
	return true
}

func validateVotingCreation(transaction transaction_specific.TxVotingCreation, identityProvider *identity_provider.IdentityProvider) bool {
	// TODO: think of date validation
	for _, pubKey := range transaction.Whitelist {
		if !identityProvider.CheckPubKeyPresence(pubKey, identity_provider.User) {
			return false
		}
	}
	return true
}

func validateVote(transaction transaction_specific.TxVote) bool {
	// TODO: add a way of getting voting by its link to check connected data
	return true
}
