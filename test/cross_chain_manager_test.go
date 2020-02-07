package test

import (
	"fmt"
	oc "github.com/ontio/multi-chain/common"
	"testing"

	"encoding/hex"
	"encoding/json"
	"github.com/ontio/multi-chain-go-sdk"
	"github.com/ontio/multi-chain-go-sdk/common"
	common2 "github.com/ontio/multi-chain/native/service/cross_chain_manager/common"
	"github.com/ontio/ontology-crypto/signature"
)

//const (
//	TestNet = "172.168.3.73"
//)

func TestRegisterSideChain(t *testing.T) {
	sdk := multi_chain_go_sdk.NewMultiChainSdk()
	pri, _ := oc.HexToBytes("5f2fe68215476abb9852cfa7da31ef00aa1468782d5ca809da5c4e1390b8ee45")
	signer, _ := multi_chain_go_sdk.NewAccountFromPrivateKey(pri, signature.SHA256withECDSA)
	//to, _ := oc.AddressFromBase58("ASUwFccvYFrrWR6vsZhhNszLFNvCLA5qS6")
	sdk.NewWebSocketClient().Connect("ws://138.91.6.125:40335")
	//sdk.NewWebSocketClient().Connect("ws://192.168.3.144:40335")

	var address = "AQf4Mzu1YJrhz9f3aRkkw9n3qhXGSh4p"
	//txHash1, _ := oc.HexToBytes("7575526bc066a3acc6 abb134119cd6d4a9041969")

	txHash, err := sdk.Native.Scm.RegisterSideChain(address, 234, 1, "chain167", 1, signer)

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

func TestGetMerkleProof(t *testing.T) {
	sdk := multi_chain_go_sdk.NewMultiChainSdk()
	sdk.NewWebSocketClient().Connect("ws://138.91.6.125:40335")
	merkleProof, err := sdk.ClientMgr.GetMerkleProof("2e211bf859b84dc14b2ce3ecfaa95f26ed3b9818c5a4cfeaa77dec8241c51db9")

	if err != nil {
		fmt.Printf("The error is %+v\n", err)
	}
	fmt.Printf("GetMerkleProof is %+v\n ", merkleProof)

}

func TestGetCrossStatesProof(t *testing.T) {
	sdk := multi_chain_go_sdk.NewMultiChainSdk()
	sdk.NewRpcClient().SetAddress("http://138.91.6.125:40336")
	//sdk.NewWebSocketClient().Connect("ws://192.168.3.144:40335")
	crossStatesProof, err := sdk.ClientMgr.GetCrossStatesProof(1, "k")

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
