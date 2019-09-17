package test

import (
	"testing"
	mcc "github.com/ontio/multi-chain/common"
	"github.com/ontio/ontology-crypto/signature"
	"github.com/ontio/multi-chain-go-sdk"
	mccv "github.com/ontio/multi-chain/core/validation"
	"github.com/stretchr/testify/assert"
	"fmt"
	"github.com/ontio/ontology-crypto/keypair"
)



const (
	privateK1 = "5f2fe68215476abb9852cfa7da31ef00aa1468782d5ca809da5c4e1390b8ee45"
	privateK2 = "5f2fe68215476abb9852cfa7da31ef00aa1468782d5ca809da5c4e1390b8ee45"
	privateK3 = "5f2fe68215476abb9852cfa7da31ef00aa1468782d5ca809da5c4e1390b8ee45"
)


func TestVerifyTx(t *testing.T) {
	sdk := multi_chain_go_sdk.NewMultiChainSdk()

	pri1, _ := mcc.HexToBytes(privateK1)
	signer, _ := multi_chain_go_sdk.NewAccountFromPrivateKey(pri1, signature.SHA256withECDSA)
	tx, _ := sdk.Native.Scm.NewRegisterSideChainTransaction(signer.Address.ToBase58(), 234, "chain167", 1)

	err := sdk.SignToTransaction(tx, signer)
	//sig, err := acct1.Sign(data)
	assert.Nil(t, err)
	fmt.Println("tx is ", tx.ToArray())

	err = mccv.VerifyTransaction(tx)
	fmt.Println("err is ", err)
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
	sdk := multi_chain_go_sdk.NewMultiChainSdk()

	pri1, _ := mcc.HexToBytes(privateK1)
	signer1, _ := multi_chain_go_sdk.NewAccountFromPrivateKey(pri1, signature.SHA256withECDSA)

	pri2, _ := mcc.HexToBytes(privateK1)
	signer2, _ := multi_chain_go_sdk.NewAccountFromPrivateKey(pri2, signature.SHA256withECDSA)


	tx, err := sdk.Native.Scm.NewApproveRegisterSideChainTransaction(112)

	signers := make([]*multi_chain_go_sdk.Account, 0)
	signers = append(signers, signer1)
	signers = append(signers, signer2)

	pubKeys := make([]keypair.PublicKey, 0)
	for _, acc := range signers {
		pubKeys = append(pubKeys, acc.PublicKey)
	}

	for _, signer := range signers {
		err = sdk.MultiSignToTransaction(tx, uint16((5*len(pubKeys)+6)/7), pubKeys, signer)
		if err != nil {
			fmt.Println("multisign error is ", err)
		}
	}


	fmt.Println("tx is ", tx.ToArray())

	err = mccv.VerifyTransaction(tx)
	fmt.Println("err is ", err)
	signatureAddr, e := tx.GetSignatureAddresses()
	if e != nil {
		fmt.Println("getsignature address error is ", e)
	} else {
		for i, addr := range signatureAddr {
			fmt.Println("signature ", i, ", ", addr.ToBase58(), ", should be ", signers[i].Address.ToBase58())
		}
	}
}

