package multi_chain_go_sdk

import (
	"fmt"
	"math/big"

	sdkcom "github.com/ontio/multi-chain-go-sdk/common"
	"github.com/ontio/multi-chain/common"
	"github.com/ontio/multi-chain/core/types"
	ccm "github.com/ontio/multi-chain/native/service/cross_chain_manager"
	nccmc "github.com/ontio/multi-chain/native/service/cross_chain_manager/common"
	"github.com/ontio/multi-chain/native/service/governance/node_manager"
	"github.com/ontio/multi-chain/native/service/governance/relayer_manager"
	"github.com/ontio/multi-chain/native/service/governance/side_chain_manager"
	hs "github.com/ontio/multi-chain/native/service/header_sync"
	hsc "github.com/ontio/multi-chain/native/service/header_sync/common"
	"github.com/ontio/multi-chain/native/service/lock_proxy"
	"github.com/ontio/multi-chain/native/service/ont"
	mcnsu "github.com/ontio/multi-chain/native/service/utils"
	"github.com/ontio/multi-chain/native/states"
	"github.com/ontio/ontology-crypto/keypair"
)

var (
	OntContractAddress               = mcnsu.OntContractAddress
	OngContractAddress               = mcnsu.OngContractAddress
	HeaderSyncContractAddress        = mcnsu.HeaderSyncContractAddress
	CrossChainManagerContractAddress = mcnsu.CrossChainManagerContractAddress
	SideChainManagerContractAddress  = mcnsu.SideChainManagerContractAddress
	NodeManagerContractAddress       = mcnsu.NodeManagerContractAddress
	RelayerManagerContractAddress    = mcnsu.RelayerManagerContractAddress
	LockProxyContractAddress         = mcnsu.LockProxyContractAddress
)

var (
	TX_VERSION = byte(0)
)

var OPCODE_IN_PAYLOAD = map[byte]bool{0xc6: true, 0x6b: true, 0x6a: true, 0xc8: true, 0x6c: true, 0x68: true, 0x67: true,
	0x7c: true, 0xc1: true}

type NativeContract struct {
	mcSdk     *MultiChainSdk
	Cc        *CrossChain
	Hs        *HeaderSync
	Ccm       *CrossChainManager
	Scm       *SideChainManager
	Nm        *NodeManager
	Rm        *RelayerManager
	Ont       *Ont
	Ong       *Ong
	LockProxy *LockProxy
}

func newNativeContract(mcSdk *MultiChainSdk) *NativeContract {
	native := &NativeContract{mcSdk: mcSdk}
	native.Cc = &CrossChain{native: native, mcSdk: mcSdk}
	native.Hs = &HeaderSync{native: native, mcSdk: mcSdk}
	native.Ccm = &CrossChainManager{native: native, mcSdk: mcSdk}
	native.Scm = &SideChainManager{native: native, mcSdk: mcSdk}
	native.Nm = &NodeManager{native: native, mcSdk: mcSdk}
	native.Rm = &RelayerManager{native: native, mcSdk: mcSdk}
	native.Ont = &Ont{native: native, mcSdk: mcSdk}
	native.Ong = &Ong{native: native, mcSdk: mcSdk}
	native.LockProxy = &LockProxy{native: native, mcSdk: mcSdk}
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

func (this *NativeContract) PreExecInvokeNativeContract(
	version byte,
	contractAddress common.Address,
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

func (this *CrossChainManager) NewBtcMultiSignTransaction(chainId uint64, redeemKey string, txHash []byte, address string, signs [][]byte) (*types.Transaction, error) {

	state := &nccmc.MultiSignParam{
		ChainID:   chainId,
		RedeemKey: redeemKey,
		TxHash:    txHash,
		Address:   address,
		Signs:     signs,
	}

	sink := new(common.ZeroCopySink)
	state.Serialization(sink)

	return this.native.NewNativeInvokeTransaction(
		TX_VERSION,
		CrossChainManagerContractAddress,
		ccm.MULTI_SIGN,
		sink.Bytes())
}

func (this *CrossChainManager) BtcMultiSign(chainId uint64, redeemKey string, txHash []byte, address string, signs [][]byte, signer *Account) (common.Uint256, error) {

	tx, err := this.NewBtcMultiSignTransaction(chainId, redeemKey, txHash, address, signs)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	err = this.mcSdk.SignToTransaction(tx, signer)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	return this.mcSdk.SendTransaction(tx)
}

func (this *CrossChainManager) NewImportOuterTransferTransaction(sourceChainId uint64, txData []byte, height uint32,
	proof []byte, relayerAddress []byte, HeaderOrCrossChainMsg []byte) (*types.Transaction, error) {

	state := &nccmc.EntranceParam{
		SourceChainID:         sourceChainId,
		Height:                height,
		Proof:                 proof,
		RelayerAddress:        relayerAddress,
		Extra:                 txData,
		HeaderOrCrossChainMsg: HeaderOrCrossChainMsg,
	}

	sink := new(common.ZeroCopySink)
	state.Serialization(sink)

	return this.native.NewNativeInvokeTransaction(
		TX_VERSION,
		CrossChainManagerContractAddress,
		ccm.IMPORT_OUTER_TRANSFER_NAME,
		sink.Bytes())
}

func (this *CrossChainManager) ImportOuterTransfer(sourceChainId uint64, txData []byte, height uint32, proof []byte,
	relayerAddress []byte, HeaderOrCrossChainMsg []byte, signer *Account) (common.Uint256, error) {

	tx, err := this.NewImportOuterTransferTransaction(sourceChainId, txData, height, proof, relayerAddress, HeaderOrCrossChainMsg)
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
		TX_VERSION,
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

	return this.native.NewNativeInvokeTransaction(
		TX_VERSION,
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

func (this *HeaderSync) NewSyncCrossChainMsgTransaction(chainId uint64, address common.Address, crossChainMsg [][]byte) (*types.Transaction, error) {
	state := &hsc.SyncCrossChainMsgParam{
		ChainID:        chainId,
		Address:        address,
		CrossChainMsgs: crossChainMsg,
	}

	sink := new(common.ZeroCopySink)
	state.Serialization(sink)

	return this.native.NewNativeInvokeTransaction(
		TX_VERSION,
		HeaderSyncContractAddress,
		hs.SYNC_CROSS_CHAIN_MSG,
		sink.Bytes())
}

func (this *HeaderSync) SyncCrossChainMsg(chainId uint64, address common.Address, crossChainMsg [][]byte, signer *Account) (common.Uint256, error) {
	tx, err := this.NewSyncCrossChainMsgTransaction(chainId, address, crossChainMsg)
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

func (this *SideChainManager) NewRegisterSideChainTransaction(address common.Address, chainId, router uint64,
	name string, blocksToWait uint64, CMCCAddress []byte) (*types.Transaction, error) {
	state := &side_chain_manager.RegisterSideChainParam{
		Address:      address,
		ChainId:      chainId,
		Router:       router,
		Name:         name,
		BlocksToWait: blocksToWait,
		CCMCAddress:  CMCCAddress,
	}

	sink := new(common.ZeroCopySink)
	err := state.Serialization(sink)
	if err != nil {
		return nil, fmt.Errorf("Parameter Serilization error: %s", err)
	}

	return this.native.NewNativeInvokeTransaction(
		TX_VERSION,
		SideChainManagerContractAddress,
		side_chain_manager.REGISTER_SIDE_CHAIN,
		sink.Bytes())
}
func (this *SideChainManager) RegisterSideChain(address common.Address, chainId, router uint64, name string,
	blocksToWait uint64, CMCCAddress []byte, signer *Account) (common.Uint256, error) {
	tx, err := this.NewRegisterSideChainTransaction(address, chainId, router, name, blocksToWait, CMCCAddress)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	err = this.mcSdk.SignToTransaction(tx, signer)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	return this.mcSdk.SendTransaction(tx)
}

func (this *SideChainManager) NewApproveRegisterSideChainTransaction(chainId uint64, address common.Address) (*types.Transaction, error) {
	state := &side_chain_manager.ChainidParam{
		Chainid: chainId,
		Address: address,
	}

	sink := new(common.ZeroCopySink)
	state.Serialization(sink)

	return this.native.NewNativeInvokeTransaction(
		TX_VERSION,
		SideChainManagerContractAddress,
		side_chain_manager.APPROVE_REGISTER_SIDE_CHAIN,
		sink.Bytes())
}
func (this *SideChainManager) ApproveRegisterSideChain(chainId uint64, signer *Account) (common.Uint256, error) {
	tx, err := this.NewApproveRegisterSideChainTransaction(chainId, signer.Address)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	err = this.mcSdk.SignToTransaction(tx, signer)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	return this.mcSdk.SendTransaction(tx)
}

func (this *SideChainManager) NewUpdateSideChainTransaction(address common.Address, chainId, router uint64, name string, blocksToWait uint64) (*types.Transaction, error) {
	state := &side_chain_manager.RegisterSideChainParam{
		Address:      address,
		ChainId:      chainId,
		Router:       router,
		Name:         name,
		BlocksToWait: blocksToWait,
	}

	sink := new(common.ZeroCopySink)
	err := state.Serialization(sink)
	if err != nil {
		return nil, fmt.Errorf("Parameter Serilization error: %s", err)
	}

	return this.native.NewNativeInvokeTransaction(
		TX_VERSION,
		SideChainManagerContractAddress,
		side_chain_manager.UPDATE_SIDE_CHAIN,
		sink.Bytes())
}
func (this *SideChainManager) UpdateSideChain(address common.Address, chainId, router uint64, name string, blocksToWait uint64, signer *Account) (common.Uint256, error) {
	tx, err := this.NewUpdateSideChainTransaction(address, chainId, router, name, blocksToWait)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	err = this.mcSdk.SignToTransaction(tx, signer)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	return this.mcSdk.SendTransaction(tx)
}

func (this *SideChainManager) NewApproveUpdateSideChainTransaction(chainId uint64, address common.Address) (*types.Transaction, error) {
	state := &side_chain_manager.ChainidParam{
		Chainid: chainId,
		Address: address,
	}

	sink := new(common.ZeroCopySink)
	state.Serialization(sink)

	return this.native.NewNativeInvokeTransaction(
		TX_VERSION,
		SideChainManagerContractAddress,
		side_chain_manager.APPROVE_UPDATE_SIDE_CHAIN,
		sink.Bytes())
}
func (this *SideChainManager) ApproveUpdateSideChain(chainId uint64, signer *Account) (common.Uint256, error) {
	tx, err := this.NewApproveUpdateSideChainTransaction(chainId, signer.Address)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	err = this.mcSdk.SignToTransaction(tx, signer)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	return this.mcSdk.SendTransaction(tx)
}

func (this *SideChainManager) NewQuitSideChainTransaction(chainId uint64, address common.Address) (*types.Transaction, error) {
	state := &side_chain_manager.ChainidParam{
		Chainid: chainId,
		Address: address,
	}

	sink := new(common.ZeroCopySink)
	state.Serialization(sink)

	return this.native.NewNativeInvokeTransaction(
		TX_VERSION,
		SideChainManagerContractAddress,
		side_chain_manager.QUIT_SIDE_CHAIN,
		sink.Bytes())
}
func (this *SideChainManager) QuitSideChain(chainId uint64, signer *Account) (common.Uint256, error) {
	tx, err := this.NewQuitSideChainTransaction(chainId, signer.Address)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	err = this.mcSdk.SignToTransaction(tx, signer)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	return this.mcSdk.SendTransaction(tx)
}

func (this *SideChainManager) NewApproveQuitSideChainTransaction(chainId uint64, address common.Address) (*types.Transaction, error) {
	state := &side_chain_manager.ChainidParam{
		Chainid: chainId,
		Address: address,
	}

	sink := new(common.ZeroCopySink)
	state.Serialization(sink)

	return this.native.NewNativeInvokeTransaction(
		TX_VERSION,
		SideChainManagerContractAddress,
		side_chain_manager.APPROVE_QUIT_SIDE_CHAIN,
		sink.Bytes())
}
func (this *SideChainManager) ApproveQuitSideChain(chainId uint64, signer *Account) (common.Uint256, error) {
	tx, err := this.NewQuitSideChainTransaction(chainId, signer.Address)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	err = this.mcSdk.SignToTransaction(tx, signer)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	return this.mcSdk.SendTransaction(tx)
}

func (this *SideChainManager) NewRegisterRedeemTransaction(redeemChainID, contractChainID uint64,
	redeem []byte, cVersion uint64, contractAddress []byte, signs [][]byte) (*types.Transaction, error) {
	state := &side_chain_manager.RegisterRedeemParam{
		RedeemChainID:   redeemChainID,
		ContractChainID: contractChainID,
		Redeem:          redeem,
		CVersion:        cVersion,
		ContractAddress: contractAddress,
		Signs:           signs,
	}

	sink := new(common.ZeroCopySink)
	state.Serialization(sink)

	return this.native.NewNativeInvokeTransaction(
		TX_VERSION,
		SideChainManagerContractAddress,
		side_chain_manager.REGISTER_REDEEM,
		sink.Bytes())
}
func (this *SideChainManager) RegisterRedeem(redeemChainID, contractChainID uint64,
	redeem, contractAddress []byte, cVersion uint64, signs [][]byte, signer *Account) (common.Uint256, error) {
	tx, err := this.NewRegisterRedeemTransaction(redeemChainID, contractChainID, redeem, cVersion, contractAddress, signs)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	err = this.mcSdk.SignToTransaction(tx, signer)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	return this.mcSdk.SendTransaction(tx)
}

func (this *SideChainManager) NewSetBtcTxParamTransaction(redeem []byte, redeemId, feeRate, minChange, pver uint64, sigArr [][]byte)  (*types.Transaction, error) {
	state := &side_chain_manager.BtcTxParam{
		Detial: &side_chain_manager.BtcTxParamDetial{
			MinChange: minChange,
			FeeRate: feeRate,
			PVersion: pver,
		},
		Sigs: sigArr,
		RedeemChainId: redeemId,
		Redeem: redeem,
	}

	sink := new(common.ZeroCopySink)
	state.Serialization(sink)

	return this.native.NewNativeInvokeTransaction(
		TX_VERSION,
		SideChainManagerContractAddress,
		side_chain_manager.SET_BTC_TX_PARAM,
		sink.Bytes())
}

func (this *SideChainManager) SetBtcTxParam(redeem []byte, redeemId, feeRate, minChange, pver uint64, sigArr [][]byte,
	signer *Account) (common.Uint256, error) {
	tx, err := this.NewSetBtcTxParamTransaction(redeem, redeemId, feeRate, minChange, pver, sigArr)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	err = this.mcSdk.SignToTransaction(tx, signer)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	return this.mcSdk.SendTransaction(tx)
}

type NodeManager struct {
	mcSdk  *MultiChainSdk
	native *NativeContract
}

func (this *NodeManager) NewRegisterCandidateTransaction(peerPubkey string, address common.Address) (*types.Transaction, error) {
	state := &node_manager.RegisterPeerParam{
		PeerPubkey: peerPubkey,
		Address:    address,
	}

	sink := new(common.ZeroCopySink)
	state.Serialization(sink)

	return this.native.NewNativeInvokeTransaction(
		TX_VERSION,
		NodeManagerContractAddress,
		node_manager.REGISTER_CANDIDATE,
		sink.Bytes())
}

func (this *NodeManager) RegisterCandidate(peerPubkey string, signer *Account) (common.Uint256, error) {
	tx, err := this.NewRegisterCandidateTransaction(peerPubkey, signer.Address)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	err = this.mcSdk.SignToTransaction(tx, signer)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	return this.mcSdk.SendTransaction(tx)
}

func (this *NodeManager) NewUnRegisterCandidateTransaction(peerPubkey string, address common.Address) (*types.Transaction, error) {
	state := &node_manager.PeerParam2{
		PeerPubkey: peerPubkey,
		Address:    address,
	}

	sink := new(common.ZeroCopySink)
	state.Serialization(sink)

	return this.native.NewNativeInvokeTransaction(
		TX_VERSION,
		NodeManagerContractAddress,
		node_manager.UNREGISTER_CANDIDATE,
		sink.Bytes())
}
func (this *NodeManager) UnRegisterCandidate(peerPubkey string, signer *Account) (common.Uint256, error) {
	tx, err := this.NewUnRegisterCandidateTransaction(peerPubkey, signer.Address)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	err = this.mcSdk.SignToTransaction(tx, signer)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	return this.mcSdk.SendTransaction(tx)
}

func (this *NodeManager) NewQuitNodeTransaction(peerPubkey string, address common.Address) (*types.Transaction, error) {
	state := &node_manager.PeerParam2{
		PeerPubkey: peerPubkey,
		Address:    address,
	}

	sink := new(common.ZeroCopySink)
	state.Serialization(sink)

	return this.native.NewNativeInvokeTransaction(
		TX_VERSION,
		NodeManagerContractAddress,
		node_manager.QUIT_NODE,
		sink.Bytes())
}
func (this *NodeManager) QuitNode(peerPubkey string, signer *Account) (common.Uint256, error) {
	tx, err := this.NewQuitNodeTransaction(peerPubkey, signer.Address)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	err = this.mcSdk.SignToTransaction(tx, signer)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	return this.mcSdk.SendTransaction(tx)
}

func (this *NodeManager) NewApproveCandidateTransaction(peerPubkey string, address common.Address) (*types.Transaction, error) {
	state := &node_manager.PeerParam{
		PeerPubkey: peerPubkey,
		Address:    address,
	}

	sink := new(common.ZeroCopySink)
	state.Serialization(sink)

	return this.native.NewNativeInvokeTransaction(
		TX_VERSION,
		NodeManagerContractAddress,
		node_manager.APPROVE_CANDIDATE,
		sink.Bytes())
}

func (this *NodeManager) ApproveCandidate(peerPubkey string, signer *Account) (common.Uint256, error) {
	tx, err := this.NewApproveCandidateTransaction(peerPubkey, signer.Address)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	err = this.mcSdk.SignToTransaction(tx, signer)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	return this.mcSdk.SendTransaction(tx)
}

func (this *NodeManager) NewRejectCandidateTransaction(peerPubkey string, address common.Address) (*types.Transaction, error) {
	state := &node_manager.PeerParam{
		PeerPubkey: peerPubkey,
		Address:    address,
	}

	sink := new(common.ZeroCopySink)
	state.Serialization(sink)

	return this.native.NewNativeInvokeTransaction(
		TX_VERSION,
		NodeManagerContractAddress,
		node_manager.REGISTER_CANDIDATE,
		sink.Bytes())
}

func (this *NodeManager) RejectCandidate(peerPubkey string, signer *Account) (common.Uint256, error) {
	tx, err := this.NewRejectCandidateTransaction(peerPubkey, signer.Address)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	err = this.mcSdk.SignToTransaction(tx, signer)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	return this.mcSdk.SendTransaction(tx)
}

func (this *NodeManager) NewBlackNodeTransaction(peerPubkeyList []string, address common.Address) (*types.Transaction, error) {
	state := &node_manager.PeerListParam{
		PeerPubkeyList: peerPubkeyList,
		Address:        address,
	}

	sink := new(common.ZeroCopySink)
	state.Serialization(sink)

	return this.native.NewNativeInvokeTransaction(
		TX_VERSION,
		NodeManagerContractAddress,
		node_manager.BLACK_NODE,
		sink.Bytes())
}

func (this *NodeManager) BlackNode(peerPubkeyList []string, signer *Account) (common.Uint256, error) {
	tx, err := this.NewBlackNodeTransaction(peerPubkeyList, signer.Address)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	err = this.mcSdk.SignToTransaction(tx, signer)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	return this.mcSdk.SendTransaction(tx)
}

func (this *NodeManager) NewWhiteNodeTransaction(peerPubkey string, address common.Address) (*types.Transaction, error) {
	state := &node_manager.PeerParam{
		PeerPubkey: peerPubkey,
		Address:    address,
	}

	sink := new(common.ZeroCopySink)
	state.Serialization(sink)

	return this.native.NewNativeInvokeTransaction(
		TX_VERSION,
		NodeManagerContractAddress,
		node_manager.WHITE_NODE,
		sink.Bytes())
}

func (this *NodeManager) WhiteNode(peerPubkey string, signer *Account) (common.Uint256, error) {
	tx, err := this.NewWhiteNodeTransaction(peerPubkey, signer.Address)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	err = this.mcSdk.SignToTransaction(tx, signer)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	return this.mcSdk.SendTransaction(tx)
}

func (this *NodeManager) NewUpdateConfigTransaction(blockMsgDelay, hashMsgDelay,
	peerHandshakeTimeout, maxBlockChangeView uint32) (*types.Transaction, error) {
	state := &node_manager.UpdateConfigParam{
		Configuration: &node_manager.Configuration{
			BlockMsgDelay:        blockMsgDelay,
			HashMsgDelay:         hashMsgDelay,
			PeerHandshakeTimeout: peerHandshakeTimeout,
			MaxBlockChangeView:   maxBlockChangeView,
		},
	}

	sink := new(common.ZeroCopySink)
	state.Serialization(sink)

	return this.native.NewNativeInvokeTransaction(
		TX_VERSION,
		NodeManagerContractAddress,
		node_manager.UPDATE_CONFIG,
		sink.Bytes())
}

func (this *NodeManager) UpdateConfig(blockMsgDelay, hashMsgDelay,
	peerHandshakeTimeout, maxBlockChangeView uint32, signers []*Account) (common.Uint256, error) {
	tx, err := this.NewUpdateConfigTransaction(blockMsgDelay, hashMsgDelay, peerHandshakeTimeout, maxBlockChangeView)
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

type RelayerManager struct {
	mcSdk  *MultiChainSdk
	native *NativeContract
}

func (this *RelayerManager) NewRegisterRelayerTransaction(addressList []common.Address, address common.Address) (*types.Transaction, error) {
	state := &relayer_manager.RelayerListParam{
		AddressList: addressList,
		Address:     address,
	}

	sink := new(common.ZeroCopySink)
	state.Serialization(sink)

	return this.native.NewNativeInvokeTransaction(
		TX_VERSION,
		RelayerManagerContractAddress,
		relayer_manager.REGISTER_RELAYER,
		sink.Bytes())
}

func (this *RelayerManager) RegisterRelayer(addressList []common.Address, signer *Account) (common.Uint256, error) {
	tx, err := this.NewRegisterRelayerTransaction(addressList, signer.Address)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	err = this.mcSdk.SignToTransaction(tx, signer)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	return this.mcSdk.SendTransaction(tx)
}

func (this *RelayerManager) NewApproveRegisterRelayerTransaction(applyID uint64, address common.Address) (*types.Transaction, error) {
	state := &relayer_manager.ApproveRelayerParam{
		ID:      applyID,
		Address: address,
	}

	sink := new(common.ZeroCopySink)
	state.Serialization(sink)

	return this.native.NewNativeInvokeTransaction(
		TX_VERSION,
		RelayerManagerContractAddress,
		relayer_manager.APPROVE_REGISTER_RELAYER,
		sink.Bytes())
}

func (this *RelayerManager) ApproveRegisterRelayer(applyID uint64, signer *Account) (common.Uint256, error) {
	tx, err := this.NewApproveRegisterRelayerTransaction(applyID, signer.Address)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	err = this.mcSdk.SignToTransaction(tx, signer)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	return this.mcSdk.SendTransaction(tx)
}

func (this *RelayerManager) NewRemoveRelayerTransaction(addressList []common.Address, address common.Address) (*types.Transaction, error) {
	state := &relayer_manager.RelayerListParam{
		AddressList: addressList,
		Address:     address,
	}

	sink := new(common.ZeroCopySink)
	state.Serialization(sink)

	return this.native.NewNativeInvokeTransaction(
		TX_VERSION,
		RelayerManagerContractAddress,
		relayer_manager.REMOVE_RELAYER,
		sink.Bytes())
}

func (this *RelayerManager) RemoveRelayer(addressList []common.Address, signer *Account) (common.Uint256, error) {
	tx, err := this.NewRemoveRelayerTransaction(addressList, signer.Address)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	err = this.mcSdk.SignToTransaction(tx, signer)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	return this.mcSdk.SendTransaction(tx)
}

func (this *RelayerManager) NewApproveRemoveRelayerTransaction(removeID uint64, address common.Address) (*types.Transaction, error) {
	state := &relayer_manager.ApproveRelayerParam{
		ID:      removeID,
		Address: address,
	}

	sink := new(common.ZeroCopySink)
	state.Serialization(sink)

	return this.native.NewNativeInvokeTransaction(
		TX_VERSION,
		RelayerManagerContractAddress,
		relayer_manager.APPROVE_REMOVE_RELAYER,
		sink.Bytes())
}

func (this *RelayerManager) ApproveRemoveRelayer(removeID uint64, signer *Account) (common.Uint256, error) {
	tx, err := this.NewApproveRemoveRelayerTransaction(removeID, signer.Address)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	err = this.mcSdk.SignToTransaction(tx, signer)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	return this.mcSdk.SendTransaction(tx)
}

func (this *NodeManager) NewCommitDposTransaction() (*types.Transaction, error) {

	return this.native.NewNativeInvokeTransaction(
		TX_VERSION,
		NodeManagerContractAddress,
		node_manager.COMMIT_DPOS,
		[]byte{})
}

func (this *NodeManager) CommitDpos(signers []*Account) (common.Uint256, error) {
	tx, err := this.NewCommitDposTransaction()
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

type Ont struct {
	mcSdk  *MultiChainSdk
	native *NativeContract
}

func (this *Ont) NewTransferTransaction(from, to common.Address, amount uint64) (*types.Transaction, error) {
	state := ont.State{
		From:  from,
		To:    to,
		Value: amount,
	}
	return this.NewMultiTransferTransaction([]ont.State{state})
}

func (this *Ont) Transfer(from *Account, to common.Address, amount uint64) (common.Uint256, error) {
	tx, err := this.NewTransferTransaction(from.Address, to, amount)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	err = this.mcSdk.SignToTransaction(tx, from)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	return this.mcSdk.SendTransaction(tx)
}

func (this *Ont) NewMultiTransferTransaction(states []ont.State) (*types.Transaction, error) {
	var transfers ont.Transfers
	transfers = ont.Transfers{
		States: states,
	}

	sink := new(common.ZeroCopySink)
	transfers.Serialization(sink)

	return this.native.NewNativeInvokeTransaction(
		TX_VERSION,
		OntContractAddress,
		ont.TRANSFER_NAME,
		sink.Bytes())
}

func (this *Ont) MultiTransfer(states []ont.State, signer *Account) (common.Uint256, error) {
	tx, err := this.NewMultiTransferTransaction(states)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	err = this.mcSdk.SignToTransaction(tx, signer)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	return this.mcSdk.SendTransaction(tx)
}

func (this *Ont) NewTransferFromTransaction(sender, from, to common.Address, amount uint64) (*types.Transaction, error) {
	state := &ont.TransferFrom{
		Sender: sender,
		From:   from,
		To:     to,
		Value:  amount,
	}
	sink := new(common.ZeroCopySink)
	state.Serialization(sink)
	return this.native.NewNativeInvokeTransaction(
		TX_VERSION,
		OntContractAddress,
		ont.TRANSFERFROM_NAME,
		sink.Bytes(),
	)
}

func (this *Ont) TransferFrom(sender *Account, from, to common.Address, amount uint64) (common.Uint256, error) {
	tx, err := this.NewTransferFromTransaction(sender.Address, from, to, amount)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	err = this.mcSdk.SignToTransaction(tx, sender)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	return this.mcSdk.SendTransaction(tx)
}

func (this *Ont) NewApproveTransaction(from, to common.Address, amount uint64) (*types.Transaction, error) {
	state := ont.State{
		From:  from,
		To:    to,
		Value: amount,
	}
	sink := new(common.ZeroCopySink)
	state.Serialization(sink)
	return this.native.NewNativeInvokeTransaction(
		TX_VERSION,
		OntContractAddress,
		ont.APPROVE_NAME,
		sink.Bytes(),
	)
}

func (this *Ont) Approve(from *Account, to common.Address, amount uint64) (common.Uint256, error) {
	tx, err := this.NewApproveTransaction(from.Address, to, amount)
	if err != nil {
		return common.UINT256_EMPTY, err
	}

	err = this.mcSdk.SignToTransaction(tx, from)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	return this.mcSdk.SendTransaction(tx)
}

func (this *Ont) Allowance(from, to common.Address) (uint64, error) {
	sink := new(common.ZeroCopySink)
	sink.WriteAddress(from)
	sink.WriteAddress(to)
	preResult, err := this.native.PreExecInvokeNativeContract(
		TX_VERSION,
		OntContractAddress,
		ont.ALLOWANCE_NAME,
		sink.Bytes(),
	)
	if err != nil {
		return 0, err
	}
	allowance, err := preResult.Result.ToBigInteger()
	if err != nil {
		return 0, err
	}
	return allowance.Uint64(), nil
}

func (this *Ont) Symbol() (string, error) {
	preResult, err := this.native.PreExecInvokeNativeContract(
		TX_VERSION,
		OntContractAddress,
		ont.SYMBOL_NAME,
		nil,
	)
	if err != nil {
		return "", err
	}
	return preResult.Result.ToString()
}

func (this *Ont) BalanceOf(address common.Address) (uint64, error) {
	sink := new(common.ZeroCopySink)
	sink.WriteAddress(address)
	preResult, err := this.native.PreExecInvokeNativeContract(
		TX_VERSION,
		OntContractAddress,
		ont.BALANCEOF_NAME,
		sink.Bytes(),
	)
	if err != nil {
		return 0, err
	}
	balance, err := preResult.Result.ToBigInteger()
	if err != nil {
		return 0, err
	}
	return balance.Uint64(), nil
}

func (this *Ont) Name() (string, error) {
	preResult, err := this.native.PreExecInvokeNativeContract(
		TX_VERSION,
		OntContractAddress,
		ont.NAME_NAME,
		nil,
	)
	if err != nil {
		return "", err
	}
	return preResult.Result.ToString()
}

func (this *Ont) Decimals() (int64, error) {
	preResult, err := this.native.PreExecInvokeNativeContract(
		TX_VERSION,
		OntContractAddress,
		ont.DECIMALS_NAME,
		nil,
	)
	if err != nil {
		return 0, err
	}
	decimals, err := preResult.Result.ToBigInteger()
	if err != nil {
		return 0, err
	}
	return decimals.Int64(), nil
}

func (this *Ont) TotalSupply() (uint64, error) {
	preResult, err := this.native.PreExecInvokeNativeContract(
		TX_VERSION,
		OntContractAddress,
		ont.TOTAL_SUPPLY_NAME,
		[]byte{},
	)
	if err != nil {
		return 0, err
	}
	supply, err := preResult.Result.ToBigInteger()
	if err != nil {
		return 0, err
	}
	return supply.Uint64(), nil
}

type Ong struct {
	mcSdk  *MultiChainSdk
	native *NativeContract
}

func (this *Ong) NewTransferTransaction(from, to common.Address, amount uint64) (*types.Transaction, error) {
	state := ont.State{
		From:  from,
		To:    to,
		Value: amount,
	}
	return this.NewMultiTransferTransaction([]ont.State{state})
}

func (this *Ong) Transfer(from *Account, to common.Address, amount uint64) (common.Uint256, error) {
	tx, err := this.NewTransferTransaction(from.Address, to, amount)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	err = this.mcSdk.SignToTransaction(tx, from)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	return this.mcSdk.SendTransaction(tx)
}

func (this *Ong) NewMultiTransferTransaction(states []ont.State) (*types.Transaction, error) {
	var transfers ont.Transfers
	transfers = ont.Transfers{
		States: states,
	}

	sink := new(common.ZeroCopySink)
	transfers.Serialization(sink)

	return this.native.NewNativeInvokeTransaction(
		TX_VERSION,
		OngContractAddress,
		ont.TRANSFER_NAME,
		sink.Bytes())
}

func (this *Ong) MultiTransfer(states []ont.State, signer *Account) (common.Uint256, error) {
	tx, err := this.NewMultiTransferTransaction(states)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	err = this.mcSdk.SignToTransaction(tx, signer)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	return this.mcSdk.SendTransaction(tx)
}

func (this *Ong) NewTransferFromTransaction(sender, from, to common.Address, amount uint64) (*types.Transaction, error) {
	state := &ont.TransferFrom{
		Sender: sender,
		From:   from,
		To:     to,
		Value:  amount,
	}
	sink := new(common.ZeroCopySink)
	state.Serialization(sink)
	return this.native.NewNativeInvokeTransaction(
		TX_VERSION,
		OngContractAddress,
		ont.TRANSFERFROM_NAME,
		sink.Bytes(),
	)
}

func (this *Ong) TransferFrom(sender *Account, from, to common.Address, amount uint64) (common.Uint256, error) {
	tx, err := this.NewTransferFromTransaction(sender.Address, from, to, amount)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	err = this.mcSdk.SignToTransaction(tx, sender)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	return this.mcSdk.SendTransaction(tx)
}

func (this *Ong) NewApproveTransaction(from, to common.Address, amount uint64) (*types.Transaction, error) {
	state := ont.State{
		From:  from,
		To:    to,
		Value: amount,
	}
	sink := new(common.ZeroCopySink)
	state.Serialization(sink)
	return this.native.NewNativeInvokeTransaction(
		TX_VERSION,
		OngContractAddress,
		ont.APPROVE_NAME,
		sink.Bytes(),
	)
}

func (this *Ong) Approve(from *Account, to common.Address, amount uint64) (common.Uint256, error) {
	tx, err := this.NewApproveTransaction(from.Address, to, amount)
	if err != nil {
		return common.UINT256_EMPTY, err
	}

	err = this.mcSdk.SignToTransaction(tx, from)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	return this.mcSdk.SendTransaction(tx)
}

func (this *Ong) Allowance(from, to common.Address) (uint64, error) {
	sink := new(common.ZeroCopySink)
	sink.WriteAddress(from)
	sink.WriteAddress(to)
	preResult, err := this.native.PreExecInvokeNativeContract(
		TX_VERSION,
		OngContractAddress,
		ont.ALLOWANCE_NAME,
		sink.Bytes(),
	)
	if err != nil {
		return 0, err
	}
	allowance, err := preResult.Result.ToBigInteger()
	if err != nil {
		return 0, err
	}
	return allowance.Uint64(), nil
}

func (this *Ong) Symbol() (string, error) {
	preResult, err := this.native.PreExecInvokeNativeContract(
		TX_VERSION,
		OngContractAddress,
		ont.SYMBOL_NAME,
		nil,
	)
	if err != nil {
		return "", err
	}
	return preResult.Result.ToString()
}

func (this *Ong) BalanceOf(address common.Address) (uint64, error) {
	sink := new(common.ZeroCopySink)
	sink.WriteAddress(address)
	preResult, err := this.native.PreExecInvokeNativeContract(
		TX_VERSION,
		OngContractAddress,
		ont.BALANCEOF_NAME,
		sink.Bytes(),
	)
	if err != nil {
		return 0, err
	}
	balance, err := preResult.Result.ToBigInteger()
	if err != nil {
		return 0, err
	}
	return balance.Uint64(), nil
}

func (this *Ong) Name() (string, error) {
	preResult, err := this.native.PreExecInvokeNativeContract(
		TX_VERSION,
		OngContractAddress,
		ont.NAME_NAME,
		nil,
	)
	if err != nil {
		return "", err
	}
	return preResult.Result.ToString()
}

func (this *Ong) Decimals() (int64, error) {
	preResult, err := this.native.PreExecInvokeNativeContract(
		TX_VERSION,
		OngContractAddress,
		ont.DECIMALS_NAME,
		nil,
	)
	if err != nil {
		return 0, err
	}
	decimals, err := preResult.Result.ToBigInteger()
	if err != nil {
		return 0, err
	}
	return decimals.Int64(), nil
}

func (this *Ong) TotalSupply() (uint64, error) {
	preResult, err := this.native.PreExecInvokeNativeContract(
		TX_VERSION,
		OngContractAddress,
		ont.TOTAL_SUPPLY_NAME,
		[]byte{},
	)
	if err != nil {
		return 0, err
	}
	supply, err := preResult.Result.ToBigInteger()
	if err != nil {
		return 0, err
	}
	return supply.Uint64(), nil
}

type LockProxy struct {
	mcSdk  *MultiChainSdk
	native *NativeContract
}

func (this *LockProxy) BindProxyHash(targetChainId uint64, targetHash []byte, pubKeys []keypair.PublicKey, singers []*Account) (common.Uint256, error) {
	sink := common.NewZeroCopySink(nil)
	bindParam := &lock_proxy.BindProxyParam{TargetChainId: targetChainId, TargetHash: targetHash}
	bindParam.Serialization(sink)
	tx, err := this.native.NewNativeInvokeTransaction(
		TX_VERSION,
		LockProxyContractAddress,
		lock_proxy.BIND_PROXY_NAME,
		sink.Bytes(),
	)
	if err != nil {
		return common.UINT256_EMPTY, err
	}

	for _, singer := range singers {
		err = this.mcSdk.MultiSignToTransaction(tx, uint16((5*len(pubKeys)+6)/7), pubKeys, singer)
		if err != nil {
			return common.UINT256_EMPTY, err
		}
	}
	return this.mcSdk.SendTransaction(tx)
}

func (this *LockProxy) BindAssetHash(SourceAssetHash common.Address, targetChainId uint64, targetAssetHash []byte, assetLimit *big.Int, isTargetChainAsset bool, pubKeys []keypair.PublicKey, singers []*Account) (common.Uint256, error) {
	sink := new(common.ZeroCopySink)
	bindParam := &lock_proxy.BindAssetParam{SourceAssetHash: SourceAssetHash, TargetChainId: targetChainId, TargetAssetHash: targetAssetHash, Limit: assetLimit, IsTargetChainAsset: isTargetChainAsset}
	bindParam.Serialization(sink)
	tx, err := this.native.NewNativeInvokeTransaction(
		TX_VERSION,
		LockProxyContractAddress,
		lock_proxy.BIND_ASSET_NAME,
		sink.Bytes(),
	)
	if err != nil {
		return common.UINT256_EMPTY, err
	}

	for _, singer := range singers {
		err = this.mcSdk.MultiSignToTransaction(tx, uint16((5*len(pubKeys)+6)/7), pubKeys, singer)
		if err != nil {
			return common.UINT256_EMPTY, err
		}
	}
	return this.mcSdk.SendTransaction(tx)
}

func (this *LockProxy) Lock(sourceAssetHash common.Address, from *Account, toChainID uint64, toAddress []byte, amount uint64) (common.Uint256, error) {
	state := &lock_proxy.LockParam{
		SourceAssetHash: sourceAssetHash,
		FromAddress:     from.Address,
		ToChainID:       toChainID,
		ToAddress:       toAddress,
		Value:           amount,
	}
	sink := new(common.ZeroCopySink)
	state.Serialization(sink)
	tx, err := this.native.NewNativeInvokeTransaction(
		TX_VERSION,
		LockProxyContractAddress,
		lock_proxy.LOCK_NAME,
		sink.Bytes(),
	)
	if err != nil {
		return common.UINT256_EMPTY, err
	}

	err = this.mcSdk.SignToTransaction(tx, from)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	return this.mcSdk.SendTransaction(tx)
}

func (this *LockProxy) GetProxyHash(toChainId uint64) ([]byte, error) {
	sink := common.NewZeroCopySink(nil)
	sink.WriteVarUint(toChainId)
	preResult, err := this.native.PreExecInvokeNativeContract(
		TX_VERSION,
		LockProxyContractAddress,
		lock_proxy.GET_PROXY_HASH_NAME,
		sink.Bytes(),
	)
	if err != nil {
		return nil, err
	}
	proxyHash, err := preResult.Result.ToByteArray()
	if err != nil {
		return nil, err
	}
	return proxyHash, nil
}

type AssetHashStruct struct {
	SourceAssetAddress common.Address
	ToChainId          uint64
}

func (this *LockProxy) GetAssetHash(sourceAssetAddress common.Address, toChainId uint64) ([]byte, error) {
	sink := common.NewZeroCopySink(nil)
	sink.WriteAddress(sourceAssetAddress)
	sink.WriteVarUint(toChainId)
	preResult, err := this.native.PreExecInvokeNativeContract(
		TX_VERSION,
		LockProxyContractAddress,
		lock_proxy.GET_ASSET_HASH_NAME,
		sink.Bytes(),
	)
	if err != nil {
		return nil, err
	}
	assetHash, err := preResult.Result.ToByteArray()
	if err != nil {
		return nil, err
	}
	return assetHash, nil
}

func (this *LockProxy) GetCrossedAmount(sourceAssetAddress common.Address, toChainId uint64) (uint64, error) {
	sink := common.NewZeroCopySink(nil)
	sink.WriteAddress(sourceAssetAddress)
	sink.WriteVarUint(toChainId)
	preResult, err := this.native.PreExecInvokeNativeContract(
		TX_VERSION,
		LockProxyContractAddress,
		lock_proxy.GET_CROSSED_AMOUNT_NAME,
		sink.Bytes(),
	)
	if err != nil {
		return 0, err
	}
	crossedAmount, err := preResult.Result.ToBigInteger()
	return crossedAmount.Uint64(), nil
}

func (this *LockProxy) GetCrossedLimit(sourceAssetAddress common.Address, toChainId uint64) (uint64, error) {
	sink := common.NewZeroCopySink(nil)
	sink.WriteAddress(sourceAssetAddress)
	sink.WriteVarUint(toChainId)
	preResult, err := this.native.PreExecInvokeNativeContract(
		TX_VERSION,
		LockProxyContractAddress,
		lock_proxy.GET_CROSSED_LIMIT_NAME,
		sink.Bytes(),
	)
	if err != nil {
		return 0, err
	}
	crossedAmount, err := preResult.Result.ToBigInteger()
	return crossedAmount.Uint64(), nil
}
