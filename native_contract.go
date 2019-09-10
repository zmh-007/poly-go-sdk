package ontology_go_sdk

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"github.com/ontio/ontology-crypto/keypair"
	sdkcom "github.com/ontio/multi-chain-go-sdk/common"
	"github.com/ontio/multi-chain-go-sdk/utils"
	"github.com/ontio/multi-chain/common"
	"github.com/ontio/multi-chain/common/serialization"
	"github.com/ontio/multi-chain/core/types"
	"github.com/ontio/multi-chain/core/payload"
	nccmc "github.com/ontio/multi-chain/native/service/cross_chain_manager/common"
	hc "github.com/ontio/multi-chain/native/service/header_sync"
	scm "github.com/ontio/multi-chain/native/service/side_chain_manager"
	ccm "github.com/ontio/multi-chain/native/service/cross_chain_manager"
	"github.com/ontio/multi-chain/native/states"
	"github.com/ontio/multi-chain/account"
)

var (
	CrossChainContractAddress, _           = utils.AddressFromHexString("0100000000000000000000000000000000000000")
	HeaderSyncContractAddress, _           = utils.AddressFromHexString("0200000000000000000000000000000000000000")
	CrossChainManagerContractAddress, _        = utils.AddressFromHexString("0300000000000000000000000000000000000000")
	SideChainManagerContractAddress, _ = utils.AddressFromHexString("0400000000000000000000000000000000000000")
)

var (
	CROSS_CHAIN_CONTRACT_VERSION           = byte(0)
	HEADER_SYNC_CONTRACT_VERSION           = byte(0)
	CROSS_CHAIN_MANAGER_CONTRACT_VERSION        = byte(0)
	SIDE_CHAIN_MANAGER_CONTRACT_VERSION = byte(0)
)

var OPCODE_IN_PAYLOAD = map[byte]bool{0xc6: true, 0x6b: true, 0x6a: true, 0xc8: true, 0x6c: true, 0x68: true, 0x67: true,
	0x7c: true, 0xc1: true}

type NativeContract struct {
	mcSdk        *MultiChainSdk
	Cc			 *CrossChain
	Hs           *HeaderSync
	Ccm          *CrossChainManager
	Scm			 *SideChainManager
}

func newNativeContract(mcSdk *MultiChainSdk) *NativeContract {
	native := &NativeContract{mcSdk: mcSdk}
	native.Cc = &CrossChain{native: native, mcSdk: mcSdk}
	native.Hs = &HeaderSync{native: native, mcSdk: mcSdk}
	native.Ccm = &CrossChainManager{native: native, mcSdk: mcSdk}
	native.Scm = &SideChainManager{native: native, mcSdk: mcSdk}
	return native
}



func (this *NativeContract) NewNativeInvokeTransaction(
	version byte,
	contractAddress common.Address,
	method string,
	paramBytes []byte,
) (*types.Transaction, error) {

	contractInvokeParam := &states.ContractInvokeParam{Version:version, Address: contractAddress, Method:method, Args: paramBytes}
	invokeCode := new(common.ZeroCopySink)
	contractInvokeParam.Serialization(invokeCode)

	return this.mcSdk.NewInvokeTransaction(invokeCode.Bytes()), nil
}

//func (this *NativeContract) InvokeNativeContract(
//	singer *Account,
//	version byte,
//	contractAddress common.Address,
//	method string,
//	params []interface{},
//) (common.Uint256, error) {
//
//	tx, err := this.NewNativeInvokeTransaction(version, contractAddress, method, params)
//	if err != nil {
//		return common.UINT256_EMPTY, err
//	}
//	err = this.mcSdk.SignToTransaction(tx, singer)
//	if err != nil {
//		return common.UINT256_EMPTY, err
//	}
//	return this.mcSdk.SendTransaction(tx)
//}


func (this *NativeContract) PreExecInvokeNativeContract(
	contractAddress common.Address,
	version byte,
	method string,
	params []interface{},
) (*sdkcom.PreExecResult, error) {
	tx, err := this.NewNativeInvokeTransaction(version, contractAddress, method, params)
	if err != nil {
		return nil, err
	}
	return this.mcSdk.PreExecTransaction(tx)
}


type CrossChain struct {
	mcSdk  *MultiChainSdk
	native *NativeContract
}



type CrossChainManager struct {
	mcSdk  *MultiChainSdk
	native *NativeContract
}

func (this *CrossChainManager) NewVoteTransaction(fromChainId uint64, address string, txHash string) (*types.Transaction, error) {
	txHashU, e := common.Uint256FromHexString(txHash)
	if e != nil {
		fmt.Printf("txHash illegal error ", e)
		return &types.Transaction{}, fmt.Errorf("TxHash error: ", e)
	}
	txHashBs := txHashU.ToArray()
	state := &nccmc.VoteParam{
		FromChainID:  fromChainId,
		Address:    address,
		TxHash: txHashBs,
	}

	sink := new(common.ZeroCopySink)
	err := state.Serialization(sink)
	if err != nil {
		return nil, fmt.Errorf("Parameter Serilization error: %s", err)
	}

	return this.native.NewNativeInvokeTransaction(
		CROSS_CHAIN_MANAGER_CONTRACT_VERSION,
		CrossChainManagerContractAddress,
		ccm.VOTE_NAME,
		sink.Bytes())
}

func (this *CrossChainManager) Vote(fromChainId uint64, address string, txHash string, signer *Account) (common.Uint256, error) {
	tx, err := this.NewVoteTransaction(fromChainId, address, txHash)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	err = this.mcSdk.SignToTransaction(tx, signer)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	return this.mcSdk.SendTransaction(tx)
}

func (this *CrossChainManager) NewImportOuterTransferTransaction(sourceChainId uint64, txData string, height uint32, proof string, relayerAddress string, targetChainId uint64, value string) (*types.Transaction, error) {

	state := &nccmc.EntranceParam{
		SourceChainID:  sourceChainId,
		TxData:  txData,
		Height:  height,
		Proof:  proof,
		RelayerAddress:  relayerAddress,
		TargetChainID:  targetChainId,
		Value:  value,
	}

	sink := new(common.ZeroCopySink)
	err := state.Serialization(sink)
	if err != nil {
		return nil, fmt.Errorf("Parameter Serilization error: %s", err)
	}

	return this.native.NewNativeInvokeTransaction(
		CROSS_CHAIN_MANAGER_CONTRACT_VERSION,
		CrossChainManagerContractAddress,
		ccm.IMPORT_OUTER_TRANSFER_NAME,
		sink.Bytes())
}

func (this *CrossChainManager) ImportOuterTransfer(sourceChainId uint64, txData string, height uint32, proof string, relayerAddress string, targetChainId uint64, value string, signer *Account) (common.Uint256, error) {

	tx, err := this.NewImportOuterTransferTransaction(sourceChainId, txData, height, proof, relayerAddress, targetChainId, value)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	err = this.mcSdk.SignToTransaction(tx, signer)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	return this.mcSdk.SendTransaction(tx)
}


type HeaderSync struct {
	mcSdk *MultiChainSdk
	native *NativeContract
}

func (this *HeaderSync) NewSyncGenesisHeaderTransaction( genesisHeader []byte) (*types.Transaction, error) {

	state := &hc.SyncGenesisHeaderParam{
		GenesisHeader:  genesisHeader,
	}

	sink := new(common.ZeroCopySink)
	err := state.Serialization(sink)
	if err != nil {
		return nil, fmt.Errorf("Parameter Serilization error: %s", err)
	}

	return this.native.NewNativeInvokeTransaction(
		HEADER_SYNC_CONTRACT_VERSION,
		HeaderSyncContractAddress,
		hc.SYNC_GENESIS_HEADER,
		sink.Bytes())
}

func (this *HeaderSync) SyncGenesisHeader(genesisHeader []byte, signer *Account) (common.Uint256, error) {
	tx, err := this.NewSyncGenesisHeaderTransaction(genesisHeader)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	err = this.mcSdk.SignToTransaction(tx, signer)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	return this.mcSdk.SendTransaction(tx)
}


func (this *HeaderSync) NewSyncBlockHeaderTransaction(address common.Address, headers [][]byte) (*types.Transaction, error) {
	state := &hc.SyncBlockHeaderParam{
		Address:  address,
		Headers: headers,
	}

	sink := new(common.ZeroCopySink)
	err := state.Serialization(sink)
	if err != nil {
		return nil, fmt.Errorf("Parameter Serilization error: %s", err)
	}

	return this.native.NewNativeInvokeTransaction(
		HEADER_SYNC_CONTRACT_VERSION,
		HeaderSyncContractAddress,
		hc.SYNC_BLOCK_HEADER,
		sink.Bytes())
}

func (this *HeaderSync) SyncBlockHeader(address common.Address, headers [][]byte, signer *Account) (common.Uint256, error) {
	tx, err := this.NewSyncBlockHeaderTransaction(address, headers)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	err = this.mcSdk.SignToTransaction(tx, signer)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	return this.mcSdk.SendTransaction(tx)
}

func (this *HeaderSync) NewSyncConsensusPeersTransaction(address common.Address, header []byte, proof string) (*types.Transaction, error) {
	state := &hc.SyncConsensusPeerParam{
		Address:  address,
		Header: header,
		Proof: proof,
	}

	sink := new(common.ZeroCopySink)
	err := state.Serialization(sink)
	if err != nil {
		return &types.Transaction{}, fmt.Errorf("Parameter Serilization error: %s", err)
	}

	return this.native.NewNativeInvokeTransaction(
		HEADER_SYNC_CONTRACT_VERSION,
		HeaderSyncContractAddress,
		hc.SYNC_CONSENSUS_PEERS,
		sink.Bytes())
}

func (this *HeaderSync) SyncConsensusPeers(address common.Address, header []byte, proof string, signer *Account) (common.Uint256, error) {
	tx, err := this.NewSyncConsensusPeersTransaction(address, header, proof)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	err = this.mcSdk.SignToTransaction(tx, signer)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	return this.mcSdk.SendTransaction(tx)
}


type SideChainManager struct {
	mcSdk  *MultiChainSdk
	native *NativeContract
}

func (this *SideChainManager) NewGegisterSideChainTransaction(address string, chainId uint64, name string, blocksToWait uint64) (*types.Transaction, error) {

	state := &scm.RegisterSideChainParam{
		Address:  address,
		ChainId: chainId,
		Name: name,
		BlocksToWait: blocksToWait,
	}

	sink := new(common.ZeroCopySink)
	err := state.Serialization(sink)
	if err != nil {
		return nil, fmt.Errorf("Parameter Serilization error: %s", err)
	}

	return this.native.NewNativeInvokeTransaction(
		SIDE_CHAIN_MANAGER_CONTRACT_VERSION,
		SideChainManagerContractAddress,
		scm.REGISTER_SIDE_CHAIN,
		sink.Bytes())
}
func (this *SideChainManager) GegisterSideChain(address string, chainId uint64, name string, blocksToWait uint64, signer *Account) (common.Uint256, error)  {

	tx, err := this.NewGegisterSideChainTransaction(address, chainId, name, blocksToWait)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	err = this.mcSdk.SignToTransaction(tx, signer)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	return this.mcSdk.SendTransaction(tx)
}


func (this *SideChainManager) NewApproveRegisterSideChainTransaction(chainId uint64) (*types.Transaction, error) {

	state := &scm.ChainidParam{
		Chainid: chainId,
	}

	sink := new(common.ZeroCopySink)
	err := state.Serialization(sink)
	if err != nil {
		return nil, fmt.Errorf("Parameter Serilization error: %s", err)
	}

	return this.native.NewNativeInvokeTransaction(
		SIDE_CHAIN_MANAGER_CONTRACT_VERSION,
		SideChainManagerContractAddress,
		scm.APPROVE_REGISTER_SIDE_CHAIN,
		sink.Bytes())
}
func (this *SideChainManager) ApproveRegisterSideChain(chainId uint64, signer *Account) (common.Uint256, error)  {

	tx, err := this.NewGegisterSideChainTransaction(chainId)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	err = this.mcSdk.SignToTransaction(tx, signer)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	return this.mcSdk.SendTransaction(tx)
}



func (this *SideChainManager) NewUpdateSideChainTransaction(address string, chainId uint64, name string, blocksToWait uint64) (*types.Transaction, error) {

	state := &scm.RegisterSideChainParam{
		Address:  address,
		ChainId: chainId,
		Name: name,
		BlocksToWait: blocksToWait,
	}

	sink := new(common.ZeroCopySink)
	err := state.Serialization(sink)
	if err != nil {
		return nil, fmt.Errorf("Parameter Serilization error: %s", err)
	}

	return this.native.NewNativeInvokeTransaction(
		SIDE_CHAIN_MANAGER_CONTRACT_VERSION,
		SideChainManagerContractAddress,
		scm.UPDATE_SIDE_CHAIN,
		sink.Bytes())
}
func (this *SideChainManager) UpdateSideChain(address string, chainId uint64, name string, blocksToWait uint64, signer *Account) (common.Uint256, error)  {

	tx, err := this.NewGegisterSideChainTransaction(address, chainId, name, blocksToWait)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	err = this.mcSdk.SignToTransaction(tx, signer)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	return this.mcSdk.SendTransaction(tx)
}


func (this *SideChainManager) NewApproveUpdateSideChainTransaction(chainId uint64) (*types.Transaction, error) {
	state := &scm.ChainidParam{
		Chainid: chainId,
	}

	sink := new(common.ZeroCopySink)
	err := state.Serialization(sink)
	if err != nil {
		return nil, fmt.Errorf("Parameter Serilization error: %s", err)
	}

	return this.native.NewNativeInvokeTransaction(
		SIDE_CHAIN_MANAGER_CONTRACT_VERSION,
		SideChainManagerContractAddress,
		scm.APPROVE_UPDATE_SIDE_CHAIN,
		sink.Bytes())
}
func (this *SideChainManager) ApproveUpdateSideChain(chainId uint64, signer *Account) (common.Uint256, error)  {
	tx, err := this.NewApproveUpdateSideChainTransaction(chainId)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	err = this.mcSdk.SignToTransaction(tx, signer)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	return this.mcSdk.SendTransaction(tx)
}



func (this *SideChainManager) NewRemoveSideChainTransaction(chainId uint64) (*types.Transaction, error) {
	state := &scm.ChainidParam{
		Chainid: chainId,
	}

	sink := new(common.ZeroCopySink)
	err := state.Serialization(sink)
	if err != nil {
		return nil, fmt.Errorf("Parameter Serilization error: %s", err)
	}

	return this.native.NewNativeInvokeTransaction(
		SIDE_CHAIN_MANAGER_CONTRACT_VERSION,
		SideChainManagerContractAddress,
		scm.REMOVE_SIDE_CHAIN,
		sink.Bytes())
}
func (this *SideChainManager) RemoveSideChain(chainId uint64, signer *Account) (common.Uint256, error)  {
	tx, err := this.NewApproveUpdateSideChainTransaction(chainId)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	err = this.mcSdk.SignToTransaction(tx, signer)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	return this.mcSdk.SendTransaction(tx)
}

func (this *SideChainManager) NewAssetMappingTransaction(address string, assetName string, assetList []*scm.Asset) (*types.Transaction, error) {
	state := &scm.AssetMappingParam{
		Address: address,
		AssetName: assetName,
		AssetList: assetList,
	}

	sink := new(common.ZeroCopySink)
	err := state.Serialization(sink)
	if err != nil {
		return nil, fmt.Errorf("Parameter Serilization error: %s", err)
	}

	return this.native.NewNativeInvokeTransaction(
		SIDE_CHAIN_MANAGER_CONTRACT_VERSION,
		SideChainManagerContractAddress,
		scm.ASSET_MAP,
		sink.Bytes())
}
func (this *SideChainManager) AssetMapping(address string, assetName string, assetList []*scm.Asset, signer *Account) (common.Uint256, error)  {
	tx, err := this.NewAssetMappingTransaction(address, assetName, assetList)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	err = this.mcSdk.SignToTransaction(tx, signer)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	return this.mcSdk.SendTransaction(tx)
}

func (this *SideChainManager) NewApproveAssetMappingTransaction(assetName string) (*types.Transaction, error) {
	state := &scm.ApproveAssetMappingParam{
		AssetName: assetName,
	}
	sink := new(common.ZeroCopySink)
	err := state.Serialization(sink)
	if err != nil {
		return nil, fmt.Errorf("Parameter Serilization error: %s", err)
	}

	return this.native.NewNativeInvokeTransaction(
		SIDE_CHAIN_MANAGER_CONTRACT_VERSION,
		SideChainManagerContractAddress,
		scm.ASSET_MAP,
		sink.Bytes())
}

func (this *SideChainManager) ApproveAssetMapping(assetName string, signer *Account) (common.Uint256, error)  {
	tx, err := this.NewApproveAssetMappingTransaction(assetName)

	if err != nil {
		return common.UINT256_EMPTY, err
	}
	err = this.mcSdk.SignToTransaction(tx, signer)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	return this.mcSdk.SendTransaction(tx)
}


