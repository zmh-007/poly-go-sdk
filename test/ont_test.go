package test

import (
	"encoding/hex"
	"fmt"
	. "github.com/ontio/multi-chain-go-sdk"
	"github.com/ontio/multi-chain/common/constants"
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

func Test_Ont_TotalSupply_Name_Symbol_Decimals(t *testing.T) {
	testMcSdk := NewMultiChainSdk()
	testMcSdk.NewRpcClient().SetAddress(testNetUrl)
	supply, err := testMcSdk.Native.Ont.TotalSupply()
	assert.Nil(t, err)
	assert.Equal(t, supply, constants.ONT_TOTAL_SUPPLY)

	name, err := testMcSdk.Native.Ont.Name()
	assert.Nil(t, err)
	assert.Equal(t, name, constants.ONT_NAME)

	symbol, err := testMcSdk.Native.Ont.Symbol()
	assert.Nil(t, err)
	assert.Equal(t, symbol, constants.ONT_SYMBOL)

	decimals, err := testMcSdk.Native.Ont.Decimals()
	assert.Nil(t, err)
	assert.Equal(t, decimals, int64(constants.ONT_DECIMALS))
}

func Test_Ont_Transfer(t *testing.T) {
	testMcSdk = NewMultiChainSdk()
	testMcSdk.NewRpcClient().SetAddress(testNetUrl)
	testWallet, err := testMcSdk.OpenWallet(walletPath)
	if err != nil {
		fmt.Printf("account.Open error:%s\n", err)
		return
	}
	accounts := make([]*Account, 0)
	accountBalances := make([]uint64, 0)
	acctCount := testWallet.GetAccountCount()
	for i := 1; i <= acctCount; i++ {
		acctI, err := testWallet.GetAccountByIndex(i, testPasswd)
		if err != nil {
			t.Errorf("GetAccountByIndex error:%s\n", err)
			return
		}
		accounts = append(accounts, acctI)
		balanceI, err := testMcSdk.Native.Ont.BalanceOf(acctI.Address)
		if err != nil {
			t.Errorf("get balance error: wallet index = %d, balance of %s, err=%s\n", i, hex.EncodeToString(acctI.Address[:]), err)
			return
		}
		accountBalances = append(accountBalances, balanceI)
		fmt.Printf("walelt index = %d, ont balance of %s = %d\n", i, hex.EncodeToString(acctI.Address[:]), balanceI)
	}

	txHash, err := testMcSdk.Native.Ont.Transfer(nil, accounts[0], accounts[1].Address, 1)
	if err != nil {
		t.Errorf("Lock error:%s", err)
		return
	}
	testMcSdk.WaitForGenerateBlock(40*time.Second, 2)
	evts, err := testMcSdk.GetSmartContractEvent(txHash.ToHexString())
	if err != nil {
		t.Errorf("GetSmartContractEvent error:%s", err)
		return
	}
	fmt.Printf("TxHash:%s\n", txHash.ToHexString())
	fmt.Printf("State:%d\n", evts.State)
	for _, notify := range evts.Notify {
		fmt.Printf("ContractAddress:%s\n", notify.ContractAddress)
		fmt.Printf("States:%+v\n", notify.States)
	}

	newAccountBalances := make([]uint64, 0)
	for i := 0; i < acctCount; i++ {
		balanceI, err := testMcSdk.Native.Ont.BalanceOf(accounts[i].Address)
		if err != nil {
			t.Errorf("get balance error: wallet index = %d, balance of %s, err=%s\n", i, hex.EncodeToString(accounts[i].Address[:]), err)
			return
		}
		fmt.Printf("walelt index = %d, ont balance of %s = %d\n", i, hex.EncodeToString(accounts[i].Address[:]), balanceI)
		newAccountBalances = append(newAccountBalances, balanceI)
	}

	assert.Equal(t, accountBalances[0]-1, newAccountBalances[0])
	assert.Equal(t, accountBalances[1]+1, newAccountBalances[1])
}
