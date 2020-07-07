package test

import (
	"fmt"
	"github.com/ontio/ontology-crypto/keypair"
	sig "github.com/ontio/ontology-crypto/signature"
	"github.com/polynetwork/poly-go-sdk"
	"github.com/polynetwork/poly/common"
	mcc "github.com/polynetwork/poly/common"
	"github.com/polynetwork/poly/core/signature"
	"github.com/polynetwork/poly/core/types"
	"github.com/stretchr/testify/assert"
	"testing"
)

const (
	privateK1 = "5f2fe68215476abb9852cfa7da31ef00aa1468782d5ca809da5c4e1390b8ee45"
	privateK2 = "f00dd7f5356e8aee93a049bdccc44ce91169e07ea3bec9f4e0142e456fd39bae"
	privateK3 = "da213fb4cb1b12269c20307dadda35a7c89869c0c791b777fd8618d4159db99c"
)

func TestVerifyTx(t *testing.T) {
	sdk := poly_go_sdk.NewPolySdk()

	pri1, _ := mcc.HexToBytes(privateK1)
	signer, _ := poly_go_sdk.NewAccountFromPrivateKey(pri1, sig.SHA256withECDSA)
	tx, _ := sdk.Native.Scm.NewRegisterSideChainTransaction(signer.Address.ToBase58(), 234, 2, "chain167", 1)

	err := sdk.SignToTransaction(tx, signer)

	sink := common.NewZeroCopySink(nil)
	err = tx.Serialization(sink)
	assert.NoError(t, err)
	tx, err = types.TransactionFromRawBytes(sink.Bytes())

	//Hence, must do serialization
	fmt.Println("after serialization, txHash = ", tx.Hash())

	signatureAddr, e := tx.GetSignatureAddresses()
	if e != nil {
		fmt.Println("getsignature address error is ", e)
	} else {
		for i, addr := range signatureAddr {
			fmt.Println("signature ", i, ", ", addr.ToBase58(), ", should be ", signer.Address.ToBase58())
		}
	}
}

func TestMultiVerifyTx(t *testing.T) {
	sdk := poly_go_sdk.NewPolySdk()

	pri1, _ := mcc.HexToBytes(privateK1)
	signer1, _ := poly_go_sdk.NewAccountFromPrivateKey(pri1, sig.SHA256withECDSA)

	pri2, _ := mcc.HexToBytes(privateK2)
	signer2, _ := poly_go_sdk.NewAccountFromPrivateKey(pri2, sig.SHA256withECDSA)

	pri3, _ := mcc.HexToBytes(privateK3)
	signer3, _ := poly_go_sdk.NewAccountFromPrivateKey(pri3, sig.SHA256withECDSA)

	tx, err := sdk.Native.Scm.NewApproveRegisterSideChainTransaction(112)

	fmt.Println("before serialization, txHash = ", tx.Hash())

	sink := common.NewZeroCopySink(nil)
	e := tx.Serialization(sink)
	assert.NoError(t, e)

	tx, err = types.TransactionFromRawBytes(sink.Bytes())

	//Hence, must do serialization
	fmt.Println("after serialization, txHash = ", tx.Hash())

	signers := make([]*poly_go_sdk.Account, 0)
	signers = append(signers, signer1)
	signers = append(signers, signer2)
	signers = append(signers, signer3)

	//Do multi sign
	pubKeys := make([]keypair.PublicKey, 0)
	for _, acc := range signers {
		pubKeys = append(pubKeys, acc.PublicKey)
	}

	m := uint16((5*len(pubKeys) + 6) / 7)
	for _, signer := range signers {
		err = sdk.MultiSignToTransaction(tx, m, pubKeys, signer)
		if err != nil {
			fmt.Println("multisign error is ", err)
		}
	}

	//Verify Multi sign
	hash := tx.Hash()
	err = signature.VerifyMultiSignature(hash.ToArray(), tx.Sigs[0].PubKeys, int(m), tx.Sigs[0].SigData)
	fmt.Println("verifyMultiSignature err is ", err)

	// restore sign addr
	signatureAddr, e := tx.GetSignatureAddresses()

	if e != nil {
		fmt.Println("getsignature address error is ", e)
	} else {
		multiSigAddr, _ := types.AddressFromBookkeepers(pubKeys)
		assert.Nil(t, err)
		for i, addr := range signatureAddr {
			fmt.Println("signature ", i, ", ", addr.ToBase58(), ", should be ", multiSigAddr.ToBase58())
		}
	}
}
