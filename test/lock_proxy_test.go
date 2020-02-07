package test

import (
	"bytes"
	"encoding/hex"
	"fmt"
	. "github.com/ontio/multi-chain-go-sdk"
	"github.com/ontio/multi-chain/common"
	"github.com/ontio/multi-chain/common/serialization"
	common2 "github.com/ontio/multi-chain/native/service/cross_chain_manager/common"
	olp "github.com/ontio/multi-chain/native/service/ont_lock_proxy"
	"github.com/ontio/multi-chain/native/service/utils"
	"github.com/ontio/ontology-crypto/keypair"
	ontutils "github.com/ontio/ontology/smartcontract/service/native/utils"
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

func Test_ONT_Transfer(t *testing.T) {

	Init()
	testMcSdk := NewMultiChainSdk()
	testMcSdk.NewRpcClient().SetAddress(testNetUrl)

	testWallet, _ = testMcSdk.OpenWallet(walletPath)
	acct1, _ := testWallet.GetAccountByIndex(1, testPasswd)
	res, err := testMcSdk.Native.Ont.BalanceOf(acct1.Address)
	if err != nil {
		t.Errorf("BalanceOf(%s) error:%s\n", hex.EncodeToString(acct1.Address[:]), err)
	}
	fmt.Printf("balance of wallet.Account1 %s is %d\n", hex.EncodeToString(acct1.Address[:]), res)
	acct2, _ := testWallet.GetAccountByIndex(2, testPasswd)
	res, err = testMcSdk.Native.Ont.BalanceOf(acct2.Address)
	if err != nil {
		t.Errorf("readuint64 error:%s\n", err)
	}
	fmt.Printf("balance of wallet.Account1 %s is %d\n", hex.EncodeToString(acct2.Address[:]), res)

	txHash, err := testMcSdk.Native.Ont.Transfer(nil, acct1, acct2.Address, 1)
	if err != nil {
		t.Errorf("Lock error:%s", err)
		return
	}
	fmt.Printf("txHash is %s\n", txHash.ToHexString())
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

	res, err = testMcSdk.Native.Ont.BalanceOf(acct1.Address)
	if err != nil {
		t.Errorf("readuint64 error:%s\n", err)
	}
	fmt.Printf("balance of wallet.Account1 %s is %d\n", hex.EncodeToString(acct1.Address[:]), res)
	res, err = testMcSdk.Native.Ont.BalanceOf(acct2.Address)
	if err != nil {
		t.Errorf("readuint64 error:%s\n", err)
	}
	fmt.Printf("balance of wallet.Account1 %s is %d\n", hex.EncodeToString(acct2.Address[:]), res)

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
	res, err := testMcSdk.Native.Ont.BalanceOf(utils.OntLockProxyContractAddress)
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
	}
}
func TestOnt_Lock(t *testing.T) {
	Init()
	testMcSdk := NewMultiChainSdk()
	testMcSdk.NewRpcClient().SetAddress(testNetUrl)
	testWallet, _ = testMcSdk.OpenWallet(walletPath)
	fmt.Printf("testWalletAccount is %s\n", hex.EncodeToString(testDefAcc.Address[:]))
	toAddressBytes, _ := hex.DecodeString("6d236b330a61a15b04aa6590e634ec7a3c411850")
	txHash, err := testMcSdk.Native.OntLock.Lock(nil, OntContractAddress, testDefAcc, 3, toAddressBytes, 2)
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
	testMcSdk := NewMultiChainSdk()
	testMcSdk.NewRpcClient().SetAddress(testNetUrl)
	pks, sgners := openWalletForBind()
	txHash, err := testMcSdk.Native.OntLock.BindProxyHash(3, ontutils.OntLockContractAddress[:], pks, sgners)
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

func Test_GetBindProxy(t *testing.T) {
	Init()
	toChainId := 3
	bindProxy, err := getBindProxyHashFromStorage(uint64(toChainId))
	if err != nil && bindProxy != "" {
		t.Errorf("Cannot get bind asset hash, err:%s", err)
	}
	fmt.Printf("GetBindProxyHash(%d) = %s\n", toChainId, bindProxy)
}

func TestOnt_BindAsset(t *testing.T) {
	Init()
	testMcSdk := NewMultiChainSdk()
	testMcSdk.NewRpcClient().SetAddress(testNetUrl)
	pks, sgners := openWalletForBind()
	fmt.Printf("done")
	txHash, err := testMcSdk.Native.OntLock.BindAssetHash(OntContractAddress, 3, ontutils.OntContractAddress[:], pks, sgners)
	if err != nil {
		t.Errorf("BindAssetHash error:%s", err)
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

func Test_GetBindAssetHash(t *testing.T) {
	Init()
	sourceAssetHash := OntContractAddress
	toChainId := 3
	bindProxy, err := getBindAssetHashFromStorage(sourceAssetHash, uint64(toChainId))
	if err != nil && bindProxy != "" {
		t.Errorf("Cannot get bind asset hash, err:%s", err)
	}
	fmt.Printf("GetBindAssetHash(%s, %d) = %s\n", hex.EncodeToString(sourceAssetHash[:]), toChainId, bindProxy)
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
		//fmt.Printf("pk index:%d,  is %v\n", i, pks[i])
		//fmt.Printf("accounts index:%d, is %v\n", i, accounts[i].Address.ToBase58())
	}

	return pks, accounts

}
func paserAuditpath(path []byte) ([]byte, []byte, [][32]byte, error) {
	source := common.NewZeroCopySource(path)
	/*
		l, eof := source.NextUint64()
		if eof {
			return nil, nil, nil, nil
		}
	*/
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

func getBindProxyHashFromStorage(toChainId uint64) (string, error) {
	bs := make([]byte, 0)
	bs = append(bs, []byte(olp.BIND_PROXY_NAME)...)
	sink := common.NewZeroCopySink(nil)
	sink.WriteUint64(toChainId)
	chainIdBytes := sink.Bytes()
	bs = append(bs, chainIdBytes...)
	proxyStorage, _ := testMcSdk.GetStorage(OntLockContractAddress.ToHexString(), bs)
	ts, err := serialization.ReadVarBytes(bytes.NewBuffer(proxyStorage))
	if err != nil {
		return "", fmt.Errorf("readVarBytes error:%s", err)
	}
	return hex.EncodeToString(ts), nil
}

func getBindAssetHashFromStorage(assetHash common.Address, toChainId uint64) (string, error) {
	bs := make([]byte, 0)
	bs = append(bs, []byte(olp.BIND_ASSET_NAME)...)
	bs = append(bs, assetHash[:]...)
	sink := common.NewZeroCopySink(nil)
	sink.WriteUint64(toChainId)
	chainIdBytes := sink.Bytes()
	bs = append(bs, chainIdBytes...)
	assetStorage, _ := testMcSdk.GetStorage(OntLockContractAddress.ToHexString(), bs)
	ts, err := serialization.ReadVarBytes(bytes.NewBuffer(assetStorage))
	if err != nil {
		return "", fmt.Errorf("readVarBytes error:%s", err)
	}
	return hex.EncodeToString(ts), nil
}
