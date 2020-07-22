/*
* Copyright (C) 2020 The poly network Authors
* This file is part of The poly network library.
*
* The poly network is free software: you can redistribute it and/or modify
* it under the terms of the GNU Lesser General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
*
* The poly network is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
* GNU Lesser General Public License for more details.
* You should have received a copy of the GNU Lesser General Public License
* along with The poly network . If not, see <http://www.gnu.org/licenses/>.
 */
package test

import (
	"encoding/hex"
	"fmt"
	"github.com/ontio/ontology-crypto/keypair"
	sig "github.com/ontio/ontology-crypto/signature"
	"github.com/polynetwork/poly-go-sdk"
	"github.com/polynetwork/poly/common"
	mcc "github.com/polynetwork/poly/common"
	"github.com/polynetwork/poly/core/signature"
	"github.com/polynetwork/poly/core/types"
	"github.com/polynetwork/poly/merkle"
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

	tx, _ := sdk.Native.Scm.NewRegisterSideChainTransaction(signer.Address, 234, 2, "chain167", 1, []byte{})

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

	tx, err := sdk.Native.Scm.NewApproveRegisterSideChainTransaction(112, common.ADDRESS_EMPTY)

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

func Test_GetAndVerify_BlockRootMerkleProof(t *testing.T) {
	sdk := poly_go_sdk.NewPolySdk()
	sdk.NewRpcClient().SetAddress("http://" + LocalNet + ":40336")
	var blockHeightToBeVerified uint32 = 10
	var blockHeightReliable uint32 = 20

	merkleProof, err := sdk.ClientMgr.GetMerkleProof(blockHeightToBeVerified, blockHeightReliable)
	assert.Nil(t, err)
	fmt.Printf("GetMerkleProof is %+v\n ", merkleProof)

	blockHeaderReliable, err := sdk.GetHeaderByHeight(blockHeightReliable)
	assert.Nil(t, err)
	blockRootReliable := blockHeaderReliable.BlockRoot

	headerToBeVerified, err := sdk.GetHeaderByHeight(blockHeightToBeVerified)
	assert.Nil(t, err)
	blockHashToBeVerified := headerToBeVerified.Hash()

	path, err := hex.DecodeString(merkleProof.AuditPath)
	val, err := merkle.MerkleProve(path, blockRootReliable.ToArray())
	assert.Nil(t, err, "Verify failed")
	assert.Equal(t, blockHashToBeVerified.ToArray(), val)
}
