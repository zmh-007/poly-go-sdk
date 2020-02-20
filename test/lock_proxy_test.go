package test

import (
	"encoding/hex"
	"fmt"
	. "github.com/ontio/multi-chain-go-sdk"
	"github.com/ontio/multi-chain/common"
	"github.com/ontio/multi-chain/common/constants"
	common2 "github.com/ontio/multi-chain/native/service/cross_chain_manager/common"
	"github.com/ontio/multi-chain/native/service/utils"
	"github.com/ontio/ontology-crypto/keypair"
	ontutils "github.com/ontio/ontology/smartcontract/service/native/utils"
	"math/big"
	"testing"
	"time"
)

var (
	testMcSdk    *MultiChainSdk
	testWallet   *Wallet
	testPasswd   = []byte("passwordtest")
	testDefAcc   *Account
	testGasPrice = uint64(0)
	testGasLimit = uint64(20000)
	testNetUrl   = "http://172.168.3.78:40336"
	walletPath   = "./alliance-wallets/wallet.dat"
)

func Init() {
	testMcSdk = NewMultiChainSdk()
	testMcSdk.NewRpcClient().SetAddress(testNetUrl)
	var err error
	var wallet *Wallet
	if !common.FileExisted(walletPath) {
		wallet, err = testMcSdk.CreateWallet(walletPath)
		if err != nil {
			fmt.Println("[CreateWallet] error:", err)
			return
		}
	} else {
		wallet, err = testMcSdk.OpenWallet(walletPath)
		if err != nil {
			fmt.Println("[CreateWallet] error:", err)
			return
		}

	}
	_, err = wallet.NewDefaultSettingAccount(testPasswd)
	if err != nil {
		fmt.Println("")
		return
	}
	//wallet.Save()
	testWallet, err = testMcSdk.OpenWallet(walletPath)
	if err != nil {
		fmt.Printf("account.Open error:%s\n", err)
		return
	}
	testDefAcc, err = testWallet.GetDefaultAccount(testPasswd)
	if err != nil {
		fmt.Printf("GetDefaultAccount error:%s\n", err)
		return
	}

	return

}

func Test_Ont_BalanceOf_Base58_Format(t *testing.T) {
	Init()
	addr, _ := common.AddressFromBase58("AJq9fNeGfk8fsherPuj3ZLXSq1BJoSerF9")
	res := hex.EncodeToString(addr[:])
	fmt.Printf("hex format address  is %s\n", res)

	testMcSdk := NewMultiChainSdk()
	testMcSdk.NewRpcClient().SetAddress(testNetUrl)
	b, err := testMcSdk.Native.Ont.BalanceOf(addr)
	if err != nil {
		t.Errorf("BalanceOf(%s) error:%s\n", addr, err)
	}
	fmt.Printf("balance of %s is %d\n", addr.ToBase58(), b)
}

func Test_BalanceOf_OntLockContract(t *testing.T) {
	Init()
	testMcSdk := NewMultiChainSdk()
	testMcSdk.NewRpcClient().SetAddress(testNetUrl)
	fmt.Printf("")
	res, err := testMcSdk.Native.Ont.BalanceOf(utils.LockProxyContractAddress)
	if err != nil {
		t.Errorf("readuint64 error:%s\n", err)
	}
	fmt.Printf("balance is %d\n", res)
}

func Test_BalanceOf_Wallet(t *testing.T) {
	Init()
	acctCount := testWallet.GetAccountCount()

	for i := 1; i <= acctCount; i++ {
		acctI, err := testWallet.GetAccountByIndex(i, testPasswd)
		if err != nil {
			t.Errorf("GetAccountByIndex error:%s\n", err)
			return
		}
		balanceI, err := testMcSdk.Native.Ont.BalanceOf(acctI.Address)
		if err != nil {
			t.Errorf("get balance error: wallet index = %d, balance of %s, err=%s\n", i, hex.EncodeToString(acctI.Address[:]), err)
			return
		}
		fmt.Printf("walelt index = %d, ont balance of %s = %d\n", i, hex.EncodeToString(acctI.Address[:]), balanceI)
		balanceI, err = testMcSdk.Native.Ong.BalanceOf(acctI.Address)
		if err != nil {
			t.Errorf("get balance error: wallet index = %d, balance of %s, err=%s\n", i, hex.EncodeToString(acctI.Address[:]), err)
			return
		}
		fmt.Printf("walelt index = %d, ong balance of %s = %d\n", i, hex.EncodeToString(acctI.Address[:]), balanceI)
	}
	Test_GetBalanceOf_LockProxyContract(t)
}
func Test_GetBalanceOf_LockProxyContract(t *testing.T) {
	Init()
	res, err := testMcSdk.Native.Ont.BalanceOf(utils.LockProxyContractAddress)
	if err != nil {
		t.Errorf("get balance of lockContract err %s\n", err)
	}
	fmt.Printf("ont balance of LockProxyContract = %s = %d\n", hex.EncodeToString(utils.LockProxyContractAddress[:]), res)
	res, err = testMcSdk.Native.Ong.BalanceOf(utils.LockProxyContractAddress)
	if err != nil {
		t.Errorf("get balance of lockContract err %s\n", err)
	}
	fmt.Printf("ong balance of LockProxyContract = %s = %d\n", hex.EncodeToString(utils.LockProxyContractAddress[:]), res)
}

func Test_Lock(t *testing.T) {
	Init()
	testMcSdk := NewMultiChainSdk()
	testMcSdk.NewRpcClient().SetAddress(testNetUrl)
	testWallet, _ = testMcSdk.OpenWallet(walletPath)
	fmt.Printf("testWalletAccount is %s\n", hex.EncodeToString(testDefAcc.Address[:]))
	toAddressBytes, _ := hex.DecodeString("6f421994b064e343e82522048962bb5328142ce1")
	txHash, err := testMcSdk.Native.LockProxy.Lock(OntContractAddress, testDefAcc, 3, toAddressBytes, 100)
	//txHash, err := testMcSdk.Native.LockProxy.Lock(OngContractAddress, testDefAcc, 3, toAddressBytes, 100)
	if err != nil {
		t.Errorf("Lock error:%s", err)
		return
	}
	testMcSdk.WaitForGenerateBlock(30*time.Second, 2)
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
}

func TestOnt_BindProxy(t *testing.T) {
	Init()
	pks, sgners := openWalletForBind()
	txHash, err := testMcSdk.Native.LockProxy.BindProxyHash(3, ontutils.LockProxyContractAddress[:], pks, sgners)
	if err != nil {
		t.Errorf("BindProxyHash error:%s", err)
		return
	}
	testMcSdk.WaitForGenerateBlock(30*time.Second, 2)
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
}

func Test_GetProxyHash(t *testing.T) {
	Init()
	var toChainId uint64 = 3
	bindProxyHash, err := testMcSdk.Native.LockProxy.GetProxyHash(toChainId)
	if err != nil {
		t.Errorf("Cannot get bind asset hash, err:%s", err)
	}
	fmt.Printf("GetBindProxyHash(%d) = %s\n", toChainId, hex.EncodeToString(bindProxyHash))
}

func TestOnt_BindAsset(t *testing.T) {
	Init()
	pks, sgners := openWalletForBind()
	txHash, err := testMcSdk.Native.LockProxy.BindAssetHash(OntContractAddress, 3, ontutils.OntContractAddress[:], big.NewInt(0).SetUint64(constants.ONT_TOTAL_SUPPLY), true, pks, sgners)
	if err != nil {
		t.Errorf("BindAssetHash error:%s", err)
		return
	}
	testMcSdk.WaitForGenerateBlock(30*time.Second, 2)
	printSmartContractEvent(txHash.ToHexString())

	txHash, err = testMcSdk.Native.LockProxy.BindAssetHash(OngContractAddress, 3, ontutils.OngContractAddress[:], big.NewInt(0).SetUint64(constants.ONG_TOTAL_SUPPLY), true, pks, sgners)
	if err != nil {
		t.Errorf("BindAssetHash error:%s", err)
		return
	}
	testMcSdk.WaitForGenerateBlock(30*time.Second, 2)
	printSmartContractEvent(txHash.ToHexString())
}

func Test_GetAssetHash(t *testing.T) {
	Init()
	//sourceAssetHash := OntContractAddress
	sourceAssetHash := OngContractAddress
	var toChainId uint64 = 3
	bindAssetHash, err := testMcSdk.Native.LockProxy.GetAssetHash(sourceAssetHash, toChainId)
	if err != nil {
		t.Errorf("Cannot get bind asset hash, err:%s", err)
	}
	fmt.Printf("GetBindAssetHash(%s, %d) = %s\n", hex.EncodeToString(sourceAssetHash[:]), toChainId, hex.EncodeToString(bindAssetHash))
}

func Test_GetCrossedAmount(t *testing.T) {
	Init()
	//sourceAssetHash := OntContractAddress
	sourceAssetHash := OngContractAddress
	var toChainId uint64 = 3
	crossedAmount, err := testMcSdk.Native.LockProxy.GetCrossedAmount(sourceAssetHash, toChainId)
	if err != nil {
		t.Errorf("Cannot get bind asset hash, err:%s", err)
	}
	fmt.Printf("GetCrossedAmount(%s, %d) = %d\n", hex.EncodeToString(sourceAssetHash[:]), toChainId, crossedAmount)
}

func Test_GetCrossedLimit(t *testing.T) {
	Init()
	//sourceAssetHash := OntContractAddress
	sourceAssetHash := OngContractAddress
	var toChainId uint64 = 3
	crossedLimit, err := testMcSdk.Native.LockProxy.GetCrossedLimit(sourceAssetHash, toChainId)
	if err != nil {
		t.Errorf("Cannot get bind asset hash, err:%s", err)
	}
	fmt.Printf("GetCrossedLimit(%s, %d) = %d\n", hex.EncodeToString(sourceAssetHash[:]), toChainId, crossedLimit)
}

func Test_GetSmartContractEvent(t *testing.T) {

	Init()
	hashStr := "cc8b4994fce500c7bdc43b76160c67fc4e4dd68883b8bcf5c455decfbeddf652"
	testMcSdk := NewMultiChainSdk()
	testMcSdk.NewRpcClient().SetAddress(testNetUrl)

	evts, err := testMcSdk.GetSmartContractEvent(hashStr)
	if err != nil {
		t.Errorf("GetSmartContractEvent error:%s", err)
		return
	}
	fmt.Printf("TxHash:%s\n", hashStr)
	fmt.Printf("State:%d\n", evts.State)
	for _, notify := range evts.Notify {
		fmt.Printf("ContractAddress:%s\n", notify.ContractAddress)
		fmt.Printf("States:%+v\n", notify.States)
	}

}

func Test_GetCrossStateProof(t *testing.T) {

	Init()
	testMcSdk := NewMultiChainSdk()
	testMcSdk.NewRpcClient().SetAddress(testNetUrl)

	height := 40496
	key := "000000000000000000000000000000000000000372657175657374020000000000000012bd227e4f617a555cfea1df71fd995411838b88010243d11b5af1fa740a1529"
	proof, err := testMcSdk.GetCrossStatesProof(uint32(height), key)
	if err != nil {
		t.Errorf("getcross state proof error :%s\n", err)
	}
	fmt.Printf("auditpath is %s\n", proof.AuditPath)
	auditpath, _ := hex.DecodeString(proof.AuditPath)
	value, _, _, _ := paserAuditpath(auditpath)
	s := common.NewZeroCopySource(value)
	merkleValue := new(common2.ToMerkleValue)
	err = merkleValue.Deserialization(s)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("merkleValue.FromChainID :%d, merkleValue.TxHash: %x\n", merkleValue.FromChainID, merkleValue.TxHash)
	fmt.Printf("merkleValue.MaketTxParam: %v\n", merkleValue.MakeTxParam)
	fmt.Printf("merkleValue.MaketTxParam.Args: %s\n", hex.EncodeToString(merkleValue.MakeTxParam.Args))
}

func openWalletForBind() (pubKeys []keypair.PublicKey, singers []*Account) {
	testMcSdk1 := NewMultiChainSdk()
	accounts := make([]*Account, 0)
	pks := make([]keypair.PublicKey, 0)
	walletPaths := []string{
		"./alliance-wallets/peer1/wallet.dat",
		"./alliance-wallets/peer2/wallet.dat",
		"./alliance-wallets/peer3/wallet.dat",
		"./alliance-wallets/peer4/wallet.dat",
		"./alliance-wallets/peer5/wallet.dat",
		"./alliance-wallets/peer6/wallet.dat",
		"./alliance-wallets/peer7/wallet.dat",
	}
	for i, walletpath := range walletPaths {
		testWallet, err := testMcSdk1.OpenWallet(walletpath)
		if err != nil {
			fmt.Printf("account.Open index:%d, error:%s\n", i, err)
		}
		testDefAcc, err = testWallet.GetDefaultAccount([]byte("1"))
		if err != nil {
			fmt.Printf("account.GetDefaultAccount index:%d, error:%s\n", i, err)
		}
		pks = append(pks, testDefAcc.PublicKey)
		accounts = append(accounts, testDefAcc)
	}

	return pks, accounts

}
func paserAuditpath(path []byte) ([]byte, []byte, [][32]byte, error) {
	source := common.NewZeroCopySource(path)
	value, eof := source.NextVarBytes()
	if eof {
		return nil, nil, nil, nil
	}
	size := int((source.Size() - source.Pos()) / common.UINT256_SIZE)
	pos := make([]byte, 0)
	hashs := make([][32]byte, 0)
	for i := 0; i < size; i++ {
		f, eof := source.NextByte()
		if eof {
			return nil, nil, nil, nil
		}
		pos = append(pos, f)

		v, eof := source.NextHash()
		if eof {
			return nil, nil, nil, nil
		}
		var onehash [32]byte
		copy(onehash[:], (v.ToArray())[0:32])
		hashs = append(hashs, onehash)
	}

	return value, pos, hashs, nil
}
