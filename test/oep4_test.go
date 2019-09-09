
package test

import (
	"testing"
	"github.com/ontio/ontology-go-sdk"
	"github.com/ontio/ontology-go-sdk/utils"
	"fmt"
	oc "github.com/ontio/ontology/common"
	"github.com/ontio/ontology-crypto/signature"
	"errors"
	"github.com/ontio/ontology-go-sdk/common"
	"github.com/ontio/ontology-go-sdk/oep4"
	"encoding/json"
)

const (
	TestNet = "http://polaris1.ont.io"
	LocalNet = "http://127.0.0.1"
)
var contractAddr, _ = utils.AddressFromHexString("2f3a182f5daa7f1ed8fb6a3053189a7aada7d7c0")


func TestOEP4Name(t *testing.T) {
	sdk := ontology_go_sdk.NewOntologySdk()
	sdk.NewRpcClient().SetAddress(LocalNet+":20336")
	preResult, err := sdk.NeoVM.PreExecInvokeNeoVMContract(contractAddr,
		[]interface{}{"name", []interface{}{}})
	if err != nil {
		panic("error")
	}
	name, _ := preResult.Result.ToString()
	fmt.Printf(" rpc name is %s \n ", name)
}

func TestOEP4Symbol(t *testing.T) {
	sdk := ontology_go_sdk.NewOntologySdk()
	sdk.NewRestClient().SetAddress(LocalNet+":20334")
	preResult, err := sdk.NeoVM.PreExecInvokeNeoVMContract(contractAddr,
		[]interface{}{"symbol", []interface{}{}})
	if err != nil {
		panic("error")
	}
	name, _ := preResult.Result.ToString()
	fmt.Printf("rest symbol is %s \n ", name)
}

func TestOEP4Decimals(t *testing.T) {
	sdk := ontology_go_sdk.NewOntologySdk()
	sdk.NewWebSocketClient().Connect("ws://localhost:20335")
	preResult, err := sdk.NeoVM.PreExecInvokeNeoVMContract(contractAddr,
		[]interface{}{"decimals", []interface{}{}})
	if err != nil {
		fmt.Printf("error is %+v\n", err)
		panic("error")
	}
	name, _ := preResult.Result.ToInteger()
	fmt.Printf("rest symbol is %s \n ", name)
}

func TestBigNumber(t *testing.T) {
	sdk := ontology_go_sdk.NewOntologySdk()
	sdk.NewWebSocketClient().Connect("ws://localhost:20335")
	amount:= oc.BigIntFromNeoBytes([]byte{2})
	preResult, err := sdk.NeoVM.PreExecInvokeNeoVMContract(contractAddr,
		[]interface{}{"getBigNumber", []interface{}{amount}})
	if err != nil {
		fmt.Printf("error is %+v\n", err)
		panic("error")
	}
	fmt.Printf("preResult is %+v\n", preResult.Result)
	name, _:= preResult.Result.ToByteArray()
	fmt.Printf("name is %+v\n", name)
	x , _ := oc.Uint256ParseFromBytes(name)
	fmt.Printf("rest big number is %+v \n ", x)


	theBN := "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	num, err := oc.Uint256FromHexString(theBN)
	fmt.Printf("The big number is %+v \n ", num)
	fmt.Printf("the decimal number is %+v \n ", oc.BigIntFromNeoBytes(name))

}

func TestOEP4BalanceOf(t *testing.T) {
	sdk := ontology_go_sdk.NewOntologySdk()
	address, _ := oc.AddressFromBase58("AQf4Mzu1YJrhz9f3aRkkwSm9n3qhXGSh4p")
	sdk.NewWebSocketClient().Connect("ws://localhost:20335")
	preResult, err := sdk.NeoVM.PreExecInvokeNeoVMContract(contractAddr,
		[]interface{}{"balanceOf", []interface{}{address}})
	if err != nil {
		fmt.Printf("error is %+v\n", err)
		panic("error")
	}
	name, _ := preResult.Result.ToInteger()
	fmt.Printf("rest symbol is %s \n ", name)
}

func TestOEP4Transfer(t *testing.T) {
	sdk := ontology_go_sdk.NewOntologySdk()
	pri, _ := oc.HexToBytes("5f2fe68215476abb9852cfa7da31ef00aa1468782d5ca809da5c4e1390b8ee45")
	fromAcct, _ := ontology_go_sdk.NewAccountFromPrivateKey(pri, signature.SHA256withECDSA)
	amount := oc.BigIntFromNeoBytes([]byte("123456"))
	to, _ := oc.AddressFromBase58("ASUwFccvYFrrWR6vsZhhNszLFNvCLA5qS6")
	sdk.NewWebSocketClient().Connect("ws://localhost:20335")
	var gasPrice uint64 = 500
	var gasLimit uint64 = 20000
	txHash, _ := sdk.NeoVM.InvokeNeoVMContract(gasPrice, gasLimit, fromAcct, contractAddr,
		[]interface{}{"transfer", []interface{}{fromAcct.Address, to, amount}})
	var results *common.SmartContactEvent
	 //results := &common.SmartContactEvent{}
	err := errors.New("No result")
	for {
		results, err = sdk.GetSmartContractEvent(txHash.ToHexString())

		if err == nil {
			fmt.Printf("transfer result is %+v \n ", results)
			break
		}
	}
	jsonResultBytes, e := json.Marshal(results)
	if e !=  nil {
		fmt.Printf("marshal results struct error : %+v", e)
	} else {
		fmt.Printf("marshal results struct to json is %+v\n", string(jsonResultBytes))
	}
}

func TestOEP4TransferMulti(t *testing.T) {
	sdk := ontology_go_sdk.NewOntologySdk()
	fPri, _ := oc.HexToBytes("5f2fe68215476abb9852cfa7da31ef00aa1468782d5ca809da5c4e1390b8ee45")
	fromAcct, _ := ontology_go_sdk.NewAccountFromPrivateKey(fPri, signature.SHA256withECDSA)
	amount := oc.BigIntFromNeoBytes([]byte("123456"))

	tPri, _ := oc.HexToBytes("f00dd7f5356e8aee93a049bdccc44ce91169e07ea3bec9f4e0142e456fd39bae")
	toAcct, _ := ontology_go_sdk.NewAccountFromPrivateKey(tPri, signature.SHA256withECDSA)
	sdk.NewWebSocketClient().Connect("ws://localhost:20335")
	var gasPrice uint64 = 500
	var gasLimit uint64 = 20000
	args := make([]*oep4.State, 0)
	args = append(args, &oep4.State{
		From:   fromAcct.Address,
		To:     toAcct.Address,
		Amount: amount,
	})
	//args = append(args, &oep4.State{
	//	From:   toAcct.Address,
	//	To:     fromAcct.Address,
	//	Amount: amount,
	//})

	tx, err := sdk.NeoVM.NewNeoVMInvokeTransaction(gasPrice, gasLimit, contractAddr, []interface{}{"transferMulti", []interface{}{args}})
	if err != nil {
		fmt.Printf("construct transaction error: %+v\n", err)
	}

	err = sdk.SignToTransaction(tx, fromAcct)
	if err != nil {
		fmt.Printf("sign transaction error: %+v\n", err)
	}
	err = sdk.SignToTransaction(tx, toAcct)
	if err != nil {
		fmt.Printf("sign transaction error: %+v\n", err)
	}
	txHash, e := sdk.SendTransaction(tx)
	if e != nil {
		fmt.Printf("send transaction error: %+v\n", e)
	}

	var results *common.SmartContactEvent
	//results := &common.SmartContactEvent{}
	err = errors.New("No result")
	for {
		results, err = sdk.GetSmartContractEvent(txHash.ToHexString())

		if err == nil {
			fmt.Printf("transfer result is %+v \n ", results)
			break
		}
	}
	jsonResultBytes, e := json.Marshal(results)
	if e !=  nil {
		fmt.Printf("marshal results struct error : %+v", e)
	} else {
		fmt.Printf("marshal results struct to json is %+v\n", string(jsonResultBytes))
	}
}