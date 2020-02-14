package multi_chain_go_sdk

import (
	"fmt"
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
	"github.com/ontio/multi-chain/native/service/ont"
	ontlock "github.com/ontio/multi-chain/native/service/ont_lock_proxy"
	mcnsu "github.com/ontio/multi-chain/native/service/utils"
	"github.com/ontio/multi-chain/native/states"
	"github.com/ontio/ontology-crypto/keypair"
)

var (
	HeaderSyncContractAddress        = mcnsu.HeaderSyncContractAddress
	CrossChainManagerContractAddress = mcnsu.CrossChainManagerContractAddress
	SideChainManagerContractAddress  = mcnsu.SideChainManagerContractAddress
	NodeManagerContractAddress       = mcnsu.NodeManagerContractAddress
	RelayerManagerContractAddress    = mcnsu.RelayerManagerContractAddress
	OntContractAddress               = mcnsu.OntContractAddress
	OntLockContractAddress           = mcnsu.OntLockProxyContractAddress
)

var (
	TX_VERSION = byte(0)
)

var OPCODE_IN_PAYLOAD = map[byte]bool{0xc6: true, 0x6b: true, 0x6a: true, 0xc8: true, 0x6c: true, 0x68: true, 0x67: true,
	0x7c: true, 0xc1: true}

type NativeContract struct {
	mcSdk   *MultiChainSdk
	Cc      *CrossChain
	Hs      *HeaderSync
	Ccm     *CrossChainManager
	Scm     *SideChainManager
	Nm      *NodeManager
	Rm      *RelayerManager
	Ont     *Ont
	OntLock *OntLock
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
	native.OntLock = &OntLock{native: native, mcSdk: mcSdk}
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
	//if err != nil {
	//	return nil, fmt.Errorf("Parameter Serilization error: %s", err)
	//}

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

func (this *SideChainManager) NewRegisterSideChainTransaction(address string, chainId, router uint64, name string, blocksToWait uint64) (*types.Transaction, error) {

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
		side_chain_manager.REGISTER_SIDE_CHAIN,
		sink.Bytes())
}
func (this *SideChainManager) RegisterSideChain(address string, chainId, router uint64, name string, blocksToWait uint64, signer *Account) (common.Uint256, error) {

	tx, err := this.NewRegisterSideChainTransaction(address, chainId, router, name, blocksToWait)
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

	state := &side_chain_manager.ChainidParam{
		Chainid: chainId,
	}

	sink := new(common.ZeroCopySink)
	state.Serialization(sink)

	return this.native.NewNativeInvokeTransaction(
		TX_VERSION,
		SideChainManagerContractAddress,
		side_chain_manager.APPROVE_REGISTER_SIDE_CHAIN,
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

func (this *SideChainManager) NewUpdateSideChainTransaction(address string, chainId, router uint64, name string, blocksToWait uint64) (*types.Transaction, error) {

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
func (this *SideChainManager) UpdateSideChain(address string, chainId, router uint64, name string, blocksToWait uint64, signer *Account) (common.Uint256, error) {

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

func (this *SideChainManager) NewApproveUpdateSideChainTransaction(chainId uint64) (*types.Transaction, error) {
	state := &side_chain_manager.ChainidParam{
		Chainid: chainId,
	}

	sink := new(common.ZeroCopySink)
	state.Serialization(sink)

	return this.native.NewNativeInvokeTransaction(
		TX_VERSION,
		SideChainManagerContractAddress,
		side_chain_manager.APPROVE_UPDATE_SIDE_CHAIN,
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
	state := &side_chain_manager.ChainidParam{
		Chainid: chainId,
	}

	sink := new(common.ZeroCopySink)
	state.Serialization(sink)

	return this.native.NewNativeInvokeTransaction(
		TX_VERSION,
		SideChainManagerContractAddress,
		side_chain_manager.REMOVE_SIDE_CHAIN,
		sink.Bytes())
}
func (this *SideChainManager) RemoveSideChain(chainId uint64, signers []*Account) (common.Uint256, error) {
	tx, err := this.NewRemoveSideChainTransaction(chainId)
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

func (this *SideChainManager) NewRegisterRedeemTransaction(redeemChainID, contractChainID uint64,
	redeem, contractAddress []byte, address string, signs [][]byte) (*types.Transaction, error) {
	state := &side_chain_manager.RegisterRedeemParam{
		RedeemChainID:   redeemChainID,
		ContractChainID: contractChainID,
		Redeem:          redeem,
		ContractAddress: contractAddress,
		Address:         address,
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
	redeem, contractAddress []byte, address string, signs [][]byte, signer *Account) (common.Uint256, error) {
	tx, err := this.NewRegisterRedeemTransaction(redeemChainID, contractChainID, redeem, contractAddress,
		address, signs)
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

func (this *NodeManager) NewRegisterCandidateTransaction(peerPubkey string, address []byte, pos uint64) (*types.Transaction, error) {
	state := &node_manager.RegisterPeerParam{
		PeerPubkey: peerPubkey,
		Address:    address,
		Pos:        pos,
	}

	sink := new(common.ZeroCopySink)
	state.Serialization(sink)

	return this.native.NewNativeInvokeTransaction(
		TX_VERSION,
		NodeManagerContractAddress,
		node_manager.REGISTER_CANDIDATE,
		sink.Bytes())
}

func (this *NodeManager) RegisterCandidate(peerPubkey string, address []byte, pos uint64, signer *Account) (common.Uint256, error) {
	tx, err := this.NewRegisterCandidateTransaction(peerPubkey, address, pos)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	err = this.mcSdk.SignToTransaction(tx, signer)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	return this.mcSdk.SendTransaction(tx)
}

func (this *NodeManager) NewUnRegisterCandidateTransaction(peerPubkey string, address []byte) (*types.Transaction, error) {
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
func (this *NodeManager) UnRegisterCandidate(peerPubkey string, address []byte, signer *Account) (common.Uint256, error) {
	tx, err := this.NewUnRegisterCandidateTransaction(peerPubkey, address)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	err = this.mcSdk.SignToTransaction(tx, signer)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	return this.mcSdk.SendTransaction(tx)
}

func (this *NodeManager) NewQuitNodeTransaction(peerPubkey string, address []byte) (*types.Transaction, error) {
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
func (this *NodeManager) QuitNode(peerPubkey string, address []byte, signer *Account) (common.Uint256, error) {
	tx, err := this.NewUnRegisterCandidateTransaction(peerPubkey, address)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	err = this.mcSdk.SignToTransaction(tx, signer)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	return this.mcSdk.SendTransaction(tx)
}

func (this *NodeManager) NewApproveCandidateTransaction(peerPubkey string) (*types.Transaction, error) {
	state := &node_manager.PeerParam{
		PeerPubkey: peerPubkey,
	}

	sink := new(common.ZeroCopySink)
	state.Serialization(sink)

	return this.native.NewNativeInvokeTransaction(
		TX_VERSION,
		NodeManagerContractAddress,
		node_manager.APPROVE_CANDIDATE,
		sink.Bytes())
}
func (this *NodeManager) ApproveCandidate(peerPubkey string, signers []*Account) (common.Uint256, error) {
	tx, err := this.NewApproveCandidateTransaction(peerPubkey)
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

func (this *NodeManager) NewRejectCandidateTransaction(peerPubkey string) (*types.Transaction, error) {
	state := &node_manager.PeerParam{
		PeerPubkey: peerPubkey,
	}

	sink := new(common.ZeroCopySink)
	state.Serialization(sink)

	return this.native.NewNativeInvokeTransaction(
		TX_VERSION,
		NodeManagerContractAddress,
		node_manager.REGISTER_CANDIDATE,
		sink.Bytes())
}
func (this *NodeManager) RejectCandidate(peerPubkey string, signers []*Account) (common.Uint256, error) {
	tx, err := this.NewRejectCandidateTransaction(peerPubkey)
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

func (this *NodeManager) NewBlackNodeTransaction(peerPubkeyList []string) (*types.Transaction, error) {
	state := &node_manager.PeerListParam{
		PeerPubkeyList: peerPubkeyList,
	}

	sink := new(common.ZeroCopySink)
	state.Serialization(sink)

	return this.native.NewNativeInvokeTransaction(
		TX_VERSION,
		NodeManagerContractAddress,
		node_manager.BLACK_NODE,
		sink.Bytes())
}
func (this *NodeManager) BlackNode(peerPubkeyList []string, signers []*Account) (common.Uint256, error) {
	tx, err := this.NewBlackNodeTransaction(peerPubkeyList)
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

func (this *NodeManager) NewWhiteNodeTransaction(peerPubkey string) (*types.Transaction, error) {
	state := &node_manager.PeerParam{
		PeerPubkey: peerPubkey,
	}

	sink := new(common.ZeroCopySink)
	state.Serialization(sink)

	return this.native.NewNativeInvokeTransaction(
		TX_VERSION,
		NodeManagerContractAddress,
		node_manager.WHITE_NODE,
		sink.Bytes())
}
func (this *NodeManager) WhiteNode(peerPubkey string, signers []*Account) (common.Uint256, error) {
	tx, err := this.NewRejectCandidateTransaction(peerPubkey)
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

func (this *NodeManager) NewAddPosTransaction(peerPubkey string, address []byte, pos uint64) (*types.Transaction, error) {
	state := &node_manager.RegisterPeerParam{
		PeerPubkey: peerPubkey,
		Address:    address,
		Pos:        pos,
	}

	sink := new(common.ZeroCopySink)
	state.Serialization(sink)

	return this.native.NewNativeInvokeTransaction(
		TX_VERSION,
		NodeManagerContractAddress,
		node_manager.ADD_POS,
		sink.Bytes())
}

func (this *NodeManager) AddPos(peerPubkey string, address []byte, pos uint64, signer *Account) (common.Uint256, error) {
	tx, err := this.NewAddPosTransaction(peerPubkey, address, pos)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	err = this.mcSdk.SignToTransaction(tx, signer)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	return this.mcSdk.SendTransaction(tx)
}

func (this *NodeManager) NewReducePosTransaction(peerPubkey string, address []byte, pos uint64) (*types.Transaction, error) {
	state := &node_manager.RegisterPeerParam{
		PeerPubkey: peerPubkey,
		Address:    address,
		Pos:        pos,
	}

	sink := new(common.ZeroCopySink)
	state.Serialization(sink)

	return this.native.NewNativeInvokeTransaction(
		TX_VERSION,
		NodeManagerContractAddress,
		node_manager.REDUCE_POS,
		sink.Bytes())
}

func (this *NodeManager) ReducePos(peerPubkey string, address []byte, pos uint64, signer *Account) (common.Uint256, error) {
	tx, err := this.NewReducePosTransaction(peerPubkey, address, pos)
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
	peerHandshakeTimeout uint32) (*types.Transaction, error) {
	state := &node_manager.Configuration{
		BlockMsgDelay:        blockMsgDelay,
		HashMsgDelay:         hashMsgDelay,
		PeerHandshakeTimeout: peerHandshakeTimeout,
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
	peerHandshakeTimeout uint32, signers []*Account) (common.Uint256, error) {
	tx, err := this.NewUpdateConfigTransaction(blockMsgDelay, hashMsgDelay, peerHandshakeTimeout)
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

func (this *RelayerManager) NewRegisterRelayerTransaction(addressList [][]byte) (*types.Transaction, error) {
	state := &relayer_manager.RelayerListParam{
		AddressList: addressList,
	}

	sink := new(common.ZeroCopySink)
	state.Serialization(sink)

	return this.native.NewNativeInvokeTransaction(
		TX_VERSION,
		RelayerManagerContractAddress,
		relayer_manager.REGISTER_RELAYER,
		sink.Bytes())
}
func (this *RelayerManager) RegisterRelayer(addressList [][]byte, signers []*Account) (common.Uint256, error) {
	tx, err := this.NewRegisterRelayerTransaction(addressList)
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

func (this *RelayerManager) NewRemoveRelayerTransaction(addressList [][]byte) (*types.Transaction, error) {
	state := &relayer_manager.RelayerListParam{
		AddressList: addressList,
	}

	sink := new(common.ZeroCopySink)
	state.Serialization(sink)

	return this.native.NewNativeInvokeTransaction(
		TX_VERSION,
		RelayerManagerContractAddress,
		relayer_manager.REMOVE_RELAYER,
		sink.Bytes())
}
func (this *RelayerManager) RemoveRelayer(addressList [][]byte, signers []*Account) (common.Uint256, error) {
	tx, err := this.NewRemoveRelayerTransaction(addressList)
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

func (this *Ont) Transfer(payer *Account, from *Account, to common.Address, amount uint64) (common.Uint256, error) {
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

func (this *Ont) MultiTransfer(payer *Account, states []ont.State, signer *Account) (common.Uint256, error) {
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

func (this *Ont) TransferFrom(payer *Account, sender *Account, from, to common.Address, amount uint64) (common.Uint256, error) {
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

func (this *Ont) Approve(payer *Account, from *Account, to common.Address, amount uint64) (common.Uint256, error) {
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

func (this *OntLock) Allowance(from, to common.Address) (uint64, error) {
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

type OntLock struct {
	mcSdk  *MultiChainSdk
	native *NativeContract
}

func (this *OntLock) BindProxyHash(targetChainId uint64, targetHash []byte, pubKeys []keypair.PublicKey, singers []*Account) (common.Uint256, error) {
	sink := new(common.ZeroCopySink)
	bindParam := &ontlock.BindProxyParam{TargetChainId: targetChainId, TargetHash: targetHash}
	bindParam.Serialization(sink)
	tx, err := this.native.NewNativeInvokeTransaction(
		TX_VERSION,
		OntLockContractAddress,
		ontlock.BIND_PROXY_NAME,
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

func (this *OntLock) BindAssetHash(SourceAssetHash common.Address, targetChainId uint64, targetAssetHash []byte, pubKeys []keypair.PublicKey, singers []*Account) (common.Uint256, error) {
	sink := new(common.ZeroCopySink)
	bindParam := &ontlock.BindAssetParam{SourceAssetHash: SourceAssetHash, TargetChainId: targetChainId, TargetAssetHash: targetAssetHash}
	bindParam.Serialization(sink)
	tx, err := this.native.NewNativeInvokeTransaction(
		TX_VERSION,
		OntLockContractAddress,
		ontlock.BIND_ASSET_NAME,
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

func (this *OntLock) Lock(payer *Account, sourceAssetHash common.Address, from *Account, toChainID uint64, toAddress []byte, amount uint64) (common.Uint256, error) {
	state := &ontlock.LockParam{
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
		OntLockContractAddress,
		ontlock.LOCK_NAME,
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
