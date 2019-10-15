package multi_chain_go_sdk

import (
	"fmt"
	sdkcom "github.com/ontio/multi-chain-go-sdk/common"
	"github.com/ontio/multi-chain/common"
	"github.com/ontio/multi-chain/core/types"
	ccm "github.com/ontio/multi-chain/native/service/cross_chain_manager"
	nccmc "github.com/ontio/multi-chain/native/service/cross_chain_manager/common"
	hs "github.com/ontio/multi-chain/native/service/header_sync"
	hsc "github.com/ontio/multi-chain/native/service/header_sync/common"
	scm "github.com/ontio/multi-chain/native/service/side_chain_manager"
	mcnsu "github.com/ontio/multi-chain/native/service/utils"
	"github.com/ontio/multi-chain/native/states"
	"github.com/ontio/ontology-crypto/keypair"
)

var (
	HeaderSyncContractAddress        = mcnsu.HeaderSyncContractAddress
	CrossChainManagerContractAddress = mcnsu.CrossChainManagerContractAddress
	SideChainManagerContractAddress  = mcnsu.SideChainManagerContractAddress
)

var (
	HEADER_SYNC_CONTRACT_VERSION         = byte(0)
	CROSS_CHAIN_MANAGER_CONTRACT_VERSION = byte(0)
	SIDE_CHAIN_MANAGER_CONTRACT_VERSION  = byte(0)
)

var OPCODE_IN_PAYLOAD = map[byte]bool{0xc6: true, 0x6b: true, 0x6a: true, 0xc8: true, 0x6c: true, 0x68: true, 0x67: true,
	0x7c: true, 0xc1: true}

type NativeContract struct {
	mcSdk *MultiChainSdk
	Cc    *CrossChain
	Hs    *HeaderSync
	Ccm   *CrossChainManager
	Scm   *SideChainManager
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

	contractInvokeParam := &states.ContractInvokeParam{Version: version, Address: contractAddress, Method: method, Args: paramBytes}
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
	params []byte,
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

func (this *CrossChainManager) NewBtcMultiSignTransaction(txHash []byte, address string, signs [][]byte) (*types.Transaction, error) {

	state := &nccmc.MultiSignParam{
		TxHash:  txHash,
		Address: address,
		Signs:   signs,
	}

	sink := new(common.ZeroCopySink)
	state.Serialization(sink)

	return this.native.NewNativeInvokeTransaction(
		CROSS_CHAIN_MANAGER_CONTRACT_VERSION,
		CrossChainManagerContractAddress,
		ccm.MULTI_SIGN,
		sink.Bytes())
}

func (this *CrossChainManager) BtcMultiSign(txHash []byte, address string, signs [][]byte, signer *Account) (common.Uint256, error) {

	tx, err := this.NewBtcMultiSignTransaction(txHash, address, signs)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	err = this.mcSdk.SignToTransaction(tx, signer)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	return this.mcSdk.SendTransaction(tx)
}

func (this *CrossChainManager) NewVoteTransaction(address string, txHash string) (*types.Transaction, error) {
	txHashU, e := common.Uint256FromHexString(txHash)
	if e != nil {
		fmt.Printf("txHash illegal error ", e)
		return &types.Transaction{}, fmt.Errorf("TxHash error: ", e)
	}
	txHashBs := txHashU.ToArray()
	state := &nccmc.VoteParam{
		Address: address,
		TxHash:  txHashBs,
	}

	sink := new(common.ZeroCopySink)
	state.Serialization(sink)
	//if err != nil {
	//	return nil, fmt.Errorf("Parameter Serilization error: %s", err)
	//}

	return this.native.NewNativeInvokeTransaction(
		CROSS_CHAIN_MANAGER_CONTRACT_VERSION,
		CrossChainManagerContractAddress,
		ccm.VOTE_NAME,
		sink.Bytes())
}

func (this *CrossChainManager) Vote(address string, txHash string, signer *Account) (common.Uint256, error) {
	tx, err := this.NewVoteTransaction(address, txHash)
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
		TxData:         txData,
		Height:         height,
		Proof:          proof,
		RelayerAddress: relayerAddress,
		TargetChainID:  targetChainId,
		Value:          value,
	}

	sink := new(common.ZeroCopySink)
	state.Serialization(sink)
	//if err != nil {
	//	return nil, fmt.Errorf("Parameter Serilization error: %s", err)
	//}

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
	mcSdk  *MultiChainSdk
	native *NativeContract
}

func (this *HeaderSync) NewSyncGenesisHeaderTransaction(chainId uint64, genesisHeader []byte) (*types.Transaction, error) {

	state := &hsc.SyncGenesisHeaderParam{
		ChainID:       chainId,
		GenesisHeader: genesisHeader,
	}

	sink := new(common.ZeroCopySink)
	state.Serialization(sink)

	return this.native.NewNativeInvokeTransaction(
		HEADER_SYNC_CONTRACT_VERSION,
		HeaderSyncContractAddress,
		hs.SYNC_GENESIS_HEADER,
		sink.Bytes())
}

func (this *HeaderSync) SyncGenesisHeader(chainId uint64, genesisHeader []byte, signers []*Account) (common.Uint256, error) {
	tx, err := this.NewSyncGenesisHeaderTransaction(chainId, genesisHeader)
	if err != nil {
		return common.UINT256_EMPTY, err
	}

	pubKeys := make([]keypair.PublicKey, 0)
	for _, acc := range signers {
		pubKeys = append(pubKeys, acc.PublicKey)
	}

	for _, signer := range signers {
		err = this.mcSdk.MultiSignToTransaction(tx, uint16((5*len(pubKeys)+6)/7), pubKeys, signer)
		if err != nil {
			return common.UINT256_EMPTY, fmt.Errorf("multi sign failed, err: %s", err)
		}
	}

	if err != nil {
		return common.UINT256_EMPTY, err
	}
	return this.mcSdk.SendTransaction(tx)
}

func (this *HeaderSync) NewSyncBlockHeaderTransaction(chainId uint64, address common.Address, headers [][]byte) (*types.Transaction, error) {
	state := &hsc.SyncBlockHeaderParam{
		ChainID: chainId,
		Address: address,
		Headers: headers,
	}

	sink := new(common.ZeroCopySink)
	state.Serialization(sink)
	//if err != nil {
	//	return nil, fmt.Errorf("Parameter Serilization error: %s", err)
	//}

	return this.native.NewNativeInvokeTransaction(
		HEADER_SYNC_CONTRACT_VERSION,
		HeaderSyncContractAddress,
		hs.SYNC_BLOCK_HEADER,
		sink.Bytes())
}

func (this *HeaderSync) SyncBlockHeader(chainId uint64, address common.Address, headers [][]byte, signer *Account) (common.Uint256, error) {
	tx, err := this.NewSyncBlockHeaderTransaction(chainId, address, headers)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	err = this.mcSdk.SignToTransaction(tx, signer)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	return this.mcSdk.SendTransaction(tx)
}

func (this *HeaderSync) NewSyncGenesisTransaction(chainId uint64, genesisHeader []byte) (*types.Transaction, error) {
	state := &hsc.SyncGenesisHeaderParam{
		ChainID:       chainId,
		GenesisHeader: genesisHeader,
	}

	sink := new(common.ZeroCopySink)
	state.Serialization(sink)

	return this.native.NewNativeInvokeTransaction(
		HEADER_SYNC_CONTRACT_VERSION,
		HeaderSyncContractAddress,
		hs.SYNC_GENESIS_HEADER,
		sink.Bytes())
}

func (this *HeaderSync) SyncGenesisPeers(chainId uint64, genesisHeader []byte, signer *Account) (common.Uint256, error) {
	tx, err := this.NewSyncGenesisTransaction(chainId, genesisHeader)
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

func (this *SideChainManager) NewRegisterSideChainTransaction(address string, chainId uint64, name string, blocksToWait uint64) (*types.Transaction, error) {

	state := &scm.RegisterSideChainParam{
		Address:      address,
		ChainId:      chainId,
		Name:         name,
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
func (this *SideChainManager) RegisterSideChain(address string, chainId uint64, name string, blocksToWait uint64, signer *Account) (common.Uint256, error) {

	tx, err := this.NewRegisterSideChainTransaction(address, chainId, name, blocksToWait)
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
	state.Serialization(sink)

	return this.native.NewNativeInvokeTransaction(
		SIDE_CHAIN_MANAGER_CONTRACT_VERSION,
		SideChainManagerContractAddress,
		scm.APPROVE_REGISTER_SIDE_CHAIN,
		sink.Bytes())
}
func (this *SideChainManager) ApproveRegisterSideChain(chainId uint64, signers []*Account) (common.Uint256, error) {

	tx, err := this.NewApproveRegisterSideChainTransaction(chainId)
	if err != nil {
		return common.UINT256_EMPTY, err
	}

	pubKeys := make([]keypair.PublicKey, 0)
	for _, acc := range signers {
		pubKeys = append(pubKeys, acc.PublicKey)
	}

	for _, signer := range signers {
		err = this.mcSdk.MultiSignToTransaction(tx, uint16((5*len(pubKeys)+6)/7), pubKeys, signer)
		if err != nil {
			return common.UINT256_EMPTY, fmt.Errorf("multi sign failed, err: %s", err)
		}
	}

	if err != nil {
		return common.UINT256_EMPTY, err
	}
	return this.mcSdk.SendTransaction(tx)
}

func (this *SideChainManager) NewUpdateSideChainTransaction(address string, chainId uint64, name string, blocksToWait uint64) (*types.Transaction, error) {

	state := &scm.RegisterSideChainParam{
		Address:      address,
		ChainId:      chainId,
		Name:         name,
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
func (this *SideChainManager) UpdateSideChain(address string, chainId uint64, name string, blocksToWait uint64, signer *Account) (common.Uint256, error) {

	tx, err := this.NewRegisterSideChainTransaction(address, chainId, name, blocksToWait)
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
	state.Serialization(sink)

	return this.native.NewNativeInvokeTransaction(
		SIDE_CHAIN_MANAGER_CONTRACT_VERSION,
		SideChainManagerContractAddress,
		scm.APPROVE_UPDATE_SIDE_CHAIN,
		sink.Bytes())
}
func (this *SideChainManager) ApproveUpdateSideChain(chainId uint64, signers []*Account) (common.Uint256, error) {
	tx, err := this.NewApproveUpdateSideChainTransaction(chainId)
	if err != nil {
		return common.UINT256_EMPTY, err
	}

	pubKeys := make([]keypair.PublicKey, 0)
	for _, acc := range signers {
		pubKeys = append(pubKeys, acc.PublicKey)
	}

	for _, signer := range signers {
		err = this.mcSdk.MultiSignToTransaction(tx, uint16((5*len(pubKeys)+6)/7), pubKeys, signer)
		if err != nil {
			return common.UINT256_EMPTY, fmt.Errorf("multi sign failed, err: %s", err)
		}
	}

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
	state.Serialization(sink)

	return this.native.NewNativeInvokeTransaction(
		SIDE_CHAIN_MANAGER_CONTRACT_VERSION,
		SideChainManagerContractAddress,
		scm.REMOVE_SIDE_CHAIN,
		sink.Bytes())
}
func (this *SideChainManager) RemoveSideChain(chainId uint64, signer *Account) (common.Uint256, error) {
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

func (this *SideChainManager) NewAssetMappingTransaction(address string, assetName string, assetList []*scm.CrossChainContract) (*types.Transaction, error) {
	state := &scm.CrossChainContractMappingParam{
		Address:   address,
		CrossChainContractName: assetName,
		CrossChainContractList: assetList,
	}

	sink := new(common.ZeroCopySink)
	err := state.Serialization(sink)
	if err != nil {
		return nil, fmt.Errorf("Parameter Serilization error: %s", err)
	}

	return this.native.NewNativeInvokeTransaction(
		SIDE_CHAIN_MANAGER_CONTRACT_VERSION,
		SideChainManagerContractAddress,
		scm.CROSS_CHAIN_CONTRACT_MAPPING,
		sink.Bytes())
}
func (this *SideChainManager) AssetMapping(address string, assetName string, assetList []*scm.CrossChainContract, signer *Account) (common.Uint256, error) {
	tx, err := this.NewAssetMappingTransaction(address, assetName, assetList)
	if err != nil {
		return common.UINT256_EMPTY, err
	}

	err = this.mcSdk.SignToTransaction(tx, signer)
	if err != nil {
		return common.UINT256_EMPTY, err
	}

	if err != nil {
		return common.UINT256_EMPTY, err
	}
	return this.mcSdk.SendTransaction(tx)
}

func (this *SideChainManager) NewApproveAssetMappingTransaction(assetName string) (*types.Transaction, error) {
	state := &scm.ApproveCrossChainContractMappingParam{
		CrossChainContractName: assetName,
	}
	sink := new(common.ZeroCopySink)
	err := state.Serialization(sink)
	if err != nil {
		return nil, fmt.Errorf("Parameter Serilization error: %s", err)
	}

	return this.native.NewNativeInvokeTransaction(
		SIDE_CHAIN_MANAGER_CONTRACT_VERSION,
		SideChainManagerContractAddress,
		scm.APPROVE_CROSS_CHAIN_CONTRACT_MAPPING,
		sink.Bytes())
}

func (this *SideChainManager) ApproveAssetMapping(assetName string, signers []*Account) (common.Uint256, error) {
	tx, err := this.NewApproveAssetMappingTransaction(assetName)

	if err != nil {
		return common.UINT256_EMPTY, err
	}

	pubKeys := make([]keypair.PublicKey, 0)
	for _, acc := range signers {
		pubKeys = append(pubKeys, acc.PublicKey)
	}

	for _, signer := range signers {
		err = this.mcSdk.MultiSignToTransaction(tx, uint16((5*len(pubKeys)+6)/7), pubKeys, signer)
		if err != nil {
			return common.UINT256_EMPTY, fmt.Errorf("multi sign failed, err: %s", err)
		}
	}

	if err != nil {
		return common.UINT256_EMPTY, err
	}
	return this.mcSdk.SendTransaction(tx)
}
