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
	"fmt"
	oc "github.com/polynetwork/poly/common"
	"github.com/stretchr/testify/assert"
	"testing"

	"encoding/hex"
	"encoding/json"
	"github.com/ontio/ontology-crypto/signature"
	"github.com/polynetwork/poly-go-sdk"
	"github.com/polynetwork/poly-go-sdk/common"
	common2 "github.com/polynetwork/poly/native/service/cross_chain_manager/common"
)

const (
	LocalNet = "127.0.0.1"
)

func TestRegisterSideChain(t *testing.T) {
	sdk := poly_go_sdk.NewPolySdk()
	pri, _ := oc.HexToBytes("5f2fe68215476abb9852cfa7da31ef00aa1468782d5ca809da5c4e1390b8ee45")
	signer, _ := poly_go_sdk.NewAccountFromPrivateKey(pri, signature.SHA256withECDSA)
	sdk.NewWebSocketClient().Connect("ws://" + LocalNet + ":40335")
	address, _ := oc.AddressFromBase58("AQf4Mzu1YJrhz9f3aRkkw9n3qhXGSh4p")
	//txHash1, _ := oc.HexToBytes("7575526bc066a3acc6 abb134119cd6d4a9041969")

	txHash, err := sdk.Native.Scm.RegisterSideChain(address, 234, 1, "chain167", 1, []byte{}, signer)

	var results *common.SmartContactEvent
	//results := &common.SmartContactEvent{}
	if err != nil {
		fmt.Printf("The error is %+v\n", err)
	}
	for {
		results, err = sdk.GetSmartContractEvent(txHash.ToHexString())

		if err == nil {
			fmt.Printf("RegisterSideChain result is %+v \n ", results)
			break
		}
	}
	jsonResultBytes, e := json.Marshal(results)
	if e != nil {
		fmt.Printf("marshal results struct error : %+v", e)
	} else {
		fmt.Printf("marshal results struct to json is %+v\n", string(jsonResultBytes))
	}
}

func TestGetCrossStatesProof(t *testing.T) {
	sdk := poly_go_sdk.NewPolySdk()
	sdk.NewRpcClient().SetAddress("http://" + LocalNet + ":40336")
	//sdk.NewWebSocketClient().Connect("ws://192.168.3.144:40335")
	crossStatesProof, err := sdk.ClientMgr.GetCrossStatesProof(1, "yourKey")

	if err != nil {
		fmt.Printf("The error is %+v\n", err)
	}
	fmt.Printf("GetCrossStatesProof is %+v\n ", crossStatesProof)

}

func Test_DeserializeToMerkleVale(t *testing.T) {
	toMVStr := "207bb26090f1dc1907b015893894e050d5aca51c4bc5c65a210d243768b2e02eab03000000000000002052a44d75b53c706c01b3242b5870268f4744046844a28b3b2f7bec685b2cee7e086e0400000000000014179da41c9eaac82a597c4d988bc614e551395f9e0200000000000000143c2ecab519d77d20520b16227492b8621e45c1a006756e6c6f636b360014fb8ec05421a71a5e6a735001c309fb894df248a40a00000000000000000000000000000000000000000000000000000000000000"
	toMVBs, _ := hex.DecodeString(toMVStr)
	var toMV common2.ToMerkleValue
	source := oc.NewZeroCopySource(toMVBs)
	err := toMV.Deserialization(source)
	if err != nil {
		t.Errorf("deserialzie error :%s", err)
	}
	fmt.Printf("args bytes is %s\n", hex.EncodeToString(toMV.MakeTxParam.Args))
	s1 := oc.NewZeroCopySource(toMV.MakeTxParam.Args)

	argsAssetAddress, eof := s1.NextVarBytes()
	if eof {
		t.Errorf("args.NextVarBytes() error ")
	}
	argsToAddress, eof := s1.NextVarBytes()
	if eof {
		t.Errorf("args.NextVarBytes() error ")
	}
	argsValue, eof := s1.NextUint64()
	if eof {
		t.Errorf("args.NextUint64() error ")
	}
	fmt.Println("args.AssetAddress is ", hex.EncodeToString(argsAssetAddress))
	fmt.Println("args.ToAddress is ", hex.EncodeToString(argsToAddress))
	fmt.Println("args.Value is ", argsValue)
}

func Test_GetMerkleProof_ThroughWS(t *testing.T) {
	sdk := poly_go_sdk.NewPolySdk()
	sdk.NewWebSocketClient().Connect("ws://" + LocalNet + ":40335")
	_, err := sdk.ClientMgr.GetMerkleProof(1, 8)
	assert.Nil(t, err)
}

func Test_GetMerkleProof_ThroughRest(t *testing.T) {
	sdk := poly_go_sdk.NewPolySdk()
	sdk.NewRestClient().SetAddress("http://" + LocalNet + ":40334")
	_, err := sdk.ClientMgr.GetMerkleProof(1, 20)
	assert.Nil(t, err)
}
