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

func Test_Ong_TotalSupply_Name_Symbol_Decimals(t *testing.T) {
	testMcSdk := NewMultiChainSdk()
	testMcSdk.NewRpcClient().SetAddress(testNetUrl)
	supply, err := testMcSdk.Native.Ong.TotalSupply()
	assert.Nil(t, err)
	assert.Equal(t, supply, constants.ONG_TOTAL_SUPPLY)

	name, err := testMcSdk.Native.Ong.Name()
	assert.Nil(t, err)
	assert.Equal(t, name, constants.ONG_NAME)

	symbol, err := testMcSdk.Native.Ong.Symbol()
	assert.Nil(t, err)
	assert.Equal(t, symbol, constants.ONG_SYMBOL)

	decimals, err := testMcSdk.Native.Ong.Decimals()
	assert.Nil(t, err)
	assert.Equal(t, decimals, int64(constants.ONG_DECIMALS))
}

func Test_Ong_Transfer(t *testing.T) {
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
		balanceI, err := testMcSdk.Native.Ong.BalanceOf(acctI.Address)
		if err != nil {
			t.Errorf("get balance error: wallet index = %d, balance of %s, err=%s\n", i, hex.EncodeToString(acctI.Address[:]), err)
			return
		}
		accountBalances = append(accountBalances, balanceI)
		fmt.Printf("walelt index = %d, ong balance of %s = %d\n", i, hex.EncodeToString(acctI.Address[:]), balanceI)
	}

	txHash, err := testMcSdk.Native.Ong.Transfer(accounts[0], accounts[1].Address, 1)
	if err != nil {
		t.Errorf("Transfer ong error:%s", err)
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
		balanceI, err := testMcSdk.Native.Ong.BalanceOf(accounts[i].Address)
		if err != nil {
			t.Errorf("get balance error: wallet index = %d, balance of %s, err=%s\n", i, hex.EncodeToString(accounts[i].Address[:]), err)
			return
		}
		fmt.Printf("walelt index = %d, ong balance of %s = %d\n", i, hex.EncodeToString(accounts[i].Address[:]), balanceI)
		newAccountBalances = append(newAccountBalances, balanceI)
	}

	assert.Equal(t, accountBalances[0]-1, newAccountBalances[0])
	assert.Equal(t, accountBalances[1]+1, newAccountBalances[1])
}

func Test_Ong_Approve(t *testing.T) {
	testMcSdk = NewMultiChainSdk()
	testMcSdk.NewRpcClient().SetAddress(testNetUrl)
	testWallet, err := testMcSdk.OpenWallet(walletPath)
	if err != nil {
		fmt.Printf("account.Open error:%s\n", err)
		return
	}
	accounts := make([]*Account, 0)
	for i := 1; i <= 2; i++ {
		acctI, err := testWallet.GetAccountByIndex(i, testPasswd)
		if err != nil {
			t.Errorf("GetAccountByIndex error:%s\n", err)
			return
		}
		accounts = append(accounts, acctI)
	}
	// get allowance
	allowance, err := testMcSdk.Native.Ong.Allowance(accounts[0].Address, accounts[1].Address)
	if err != nil {
		t.Errorf("get allowance(%s, %s) error: err=%s\n", hex.EncodeToString(accounts[0].Address[:]), hex.EncodeToString(accounts[1].Address[:]), err)
		return
	}
	// approve(acct0, acct1, allowance + 1)
	var approveAmount uint64 = allowance + 1
	txHash, err := testMcSdk.Native.Ong.Approve(accounts[0], accounts[1].Address, approveAmount)
	if err != nil {
		t.Errorf("approve(%s, %s, %d) error: err=%s\n", hex.EncodeToString(accounts[0].Address[:]), hex.EncodeToString(accounts[1].Address[:]), approveAmount, err)
		return
	}
	testMcSdk.WaitForGenerateBlock(40*time.Second, 2)
	if err := printSmartContractEvent(txHash.ToHexString()); err != nil {
		return
	}
	// check new allowance
	newAllowance, err := testMcSdk.Native.Ong.Allowance(accounts[0].Address, accounts[1].Address)
	if err != nil {
		t.Errorf("get allowance(%s, %s) error: err=%s\n", hex.EncodeToString(accounts[0].Address[:]), hex.EncodeToString(accounts[1].Address[:]), err)
		return
	}
	assert.Equal(t, approveAmount, newAllowance)
}

func Test_Ong_TransferFrom(t *testing.T) {
	testMcSdk = NewMultiChainSdk()
	testMcSdk.NewRpcClient().SetAddress(testNetUrl)
	testWallet, err := testMcSdk.OpenWallet(walletPath)
	if err != nil {
		fmt.Printf("account.Open error:%s\n", err)
		return
	}
	accounts := make([]*Account, 0)
	accountBalances := make([]uint64, 0)
	for i := 1; i <= 2; i++ {
		acctI, err := testWallet.GetAccountByIndex(i, testPasswd)
		if err != nil {
			t.Errorf("GetAccountByIndex error:%s\n", err)
			return
		}
		accounts = append(accounts, acctI)
		balanceI, err := testMcSdk.Native.Ong.BalanceOf(acctI.Address)
		if err != nil {
			t.Errorf("get balance error: wallet index = %d, balance of %s, err=%s\n", i, hex.EncodeToString(acctI.Address[:]), err)
			return
		}
		accountBalances = append(accountBalances, balanceI)
		fmt.Printf("walelt index = %d, Ong balance of %s = %d\n", i, hex.EncodeToString(acctI.Address[:]), balanceI)
	}
	// get allowance
	allowance, err := testMcSdk.Native.Ong.Allowance(accounts[0].Address, accounts[1].Address)
	if err != nil {
		t.Errorf("get allowance(%s, %s) error: err=%s\n", hex.EncodeToString(accounts[0].Address[:]), hex.EncodeToString(accounts[1].Address[:]), err)
		return
	}
	// approve(acct0, acct1, allowance + 1)
	var approveAmount uint64 = allowance + 1
	txHash, err := testMcSdk.Native.Ong.Approve(accounts[0], accounts[1].Address, approveAmount)
	testMcSdk.WaitForGenerateBlock(30*time.Second, 2)
	if err := printSmartContractEvent(txHash.ToHexString()); err != nil {
		return
	}
	// check new allowance after approve
	allowance1, err := testMcSdk.Native.Ong.Allowance(accounts[0].Address, accounts[1].Address)
	if err != nil {
		t.Errorf("allowance(%s, %s) error: err=%s\n", hex.EncodeToString(accounts[0].Address[:]), hex.EncodeToString(accounts[1].Address[:]), err)
		return
	}
	assert.Equal(t, approveAmount, allowance1)
	// transferFrom(acct1, acct0, approvedAmount)
	txHash, err = testMcSdk.Native.Ong.TransferFrom(accounts[1], accounts[0].Address, accounts[1].Address, approveAmount)
	if err != nil {
		t.Errorf("transferFrom(%s, %s, %s, %d) error: err=%s\n", hex.EncodeToString(accounts[1].Address[:]), hex.EncodeToString(accounts[0].Address[:]), hex.EncodeToString(accounts[0].Address[:]), approveAmount, err)
		return
	}
	testMcSdk.WaitForGenerateBlock(40*time.Second, 2)
	if err := printSmartContractEvent(txHash.ToHexString()); err != nil {
		return
	}

	// check new allowance after transferFrom
	allowance2, err := testMcSdk.Native.Ong.Allowance(accounts[0].Address, accounts[1].Address)
	if err != nil {
		t.Errorf("get allowance(%s, %s) error: err=%s\n", hex.EncodeToString(accounts[0].Address[:]), hex.EncodeToString(accounts[1].Address[:]), err)
		return
	}
	assert.Equal(t, uint64(0), allowance2)

	// get new balance
	newAccountBalances := make([]uint64, 0)
	for i := 0; i < 2; i++ {
		balanceI, err := testMcSdk.Native.Ong.BalanceOf(accounts[i].Address)
		if err != nil {
			t.Errorf("get balance error: wallet index = %d, balance of %s, err=%s\n", i, hex.EncodeToString(accounts[i].Address[:]), err)
			return
		}
		fmt.Printf("walelt index = %d, Ong balance of %s = %d\n", i, hex.EncodeToString(accounts[i].Address[:]), balanceI)
		newAccountBalances = append(newAccountBalances, balanceI)
	}
	assert.Equal(t, accountBalances[0]-approveAmount, newAccountBalances[0])
	assert.Equal(t, accountBalances[1]+approveAmount, newAccountBalances[1])
}
