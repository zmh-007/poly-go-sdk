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
)

var (
	TX_VERSION = byte(0)
)

var OPCODE_IN_PAYLOAD = map[byte]bool{0xc6: true, 0x6b: true, 0x6a: true, 0xc8: true, 0x6c: true, 0x68: true, 0x67: true,
	0x7c: true, 0xc1: true}

type NativeContract struct {
	mcSdk *MultiChainSdk
	Cc    *CrossChain
	Hs    *HeaderSync
	Ccm   *CrossChainManager
	Scm   *SideChainManager
	Nm    *NodeManager
	Rm    *RelayerManager
}

func newNativeContract(mcSdk *MultiChainSdk) *NativeContract {
	native := &NativeContract{mcSdk: mcSdk}
	native.Cc = &CrossChain{native: native, mcSdk: mcSdk}
	native.Hs = &HeaderSync{native: native, mcSdk: mcSdk}
	native.Ccm = &CrossChainManager{native: native, mcSdk: mcSdk}
	native.Scm = &SideChainManager{native: native, mcSdk: mcSdk}
	native.Nm = &NodeManager{native: native, mcSdk: mcSdk}
	native.Rm = &RelayerManager{native: native, mcSdk: mcSdk}
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

func (this *CrossChainManager) NewInitRedeemScriptTransaction(redeemScript string) (*types.Transaction, error) {

	state := &nccmc.InitRedeemScriptParam{
		RedeemScript: redeemScript,
	}

	sink := new(common.ZeroCopySink)
	state.Serialization(sink)

	return this.native.NewNativeInvokeTransaction(
		TX_VERSION,
		CrossChainManagerContractAddress,
		ccm.INIT_REDEEM_SCRIPT,
		sink.Bytes())
}

func (this *CrossChainManager) InitRedeemScript(redeemScript string, signers []*Account) (common.Uint256, error) {
	tx, err := this.NewInitRedeemScriptTransaction(redeemScript)
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

func (this *CrossChainManager) NewBtcMultiSignTransaction(txHash []byte, address string, signs [][]byte) (*types.Transaction, error) {

	state := &nccmc.MultiSignParam{
		TxHash:  txHash,
		Address: address,
		Signs:   signs,
	}

	sink := new(common.ZeroCopySink)
	state.Serialization(sink)

	return this.native.NewNativeInvokeTransaction(
		TX_VERSION,
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

func (this *CrossChainManager) NewVoteTransaction(fromChainID uint64, address string, txHash string) (*types.Transaction, error) {
	txHashU, e := common.Uint256FromHexString(txHash)
	if e != nil {
		fmt.Printf("txHash illegal error ", e)
		return &types.Transaction{}, fmt.Errorf("TxHash error: ", e)
	}
	txHashBs := txHashU.ToArray()
	state := &nccmc.VoteParam{
		FromChainID: fromChainID,
		Address:     address,
		TxHash:      txHashBs,
	}

	sink := new(common.ZeroCopySink)
	state.Serialization(sink)
	//if err != nil {
	//	return nil, fmt.Errorf("Parameter Serilization error: %s", err)
	//}

	return this.native.NewNativeInvokeTransaction(
		TX_VERSION,
		CrossChainManagerContractAddress,
		ccm.VOTE_NAME,
		sink.Bytes())
}

func (this *CrossChainManager) Vote(fromChainID uint64, address string, txHash string, signer *Account) (common.Uint256, error) {
	tx, err := this.NewVoteTransaction(fromChainID, address, txHash)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	err = this.mcSdk.SignToTransaction(tx, signer)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	return this.mcSdk.SendTransaction(tx)
}

func (this *CrossChainManager) NewImportOuterTransferTransaction(sourceChainId uint64, txHash, txData []byte, height uint32,
	proof []byte, relayerAddress []byte, HeaderOrCrossChainMsg []byte) (*types.Transaction, error) {

	state := &nccmc.EntranceParam{
		SourceChainID:         sourceChainId,
		TxHash:                txHash,
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

func (this *CrossChainManager) ImportOuterTransfer(sourceChainId uint64, txHash, txData []byte, height uint32, proof []byte,
	relayerAddress []byte, HeaderOrCrossChainMsg []byte, signer *Account) (common.Uint256, error) {

	tx, err := this.NewImportOuterTransferTransaction(sourceChainId, txHash, txData, height, proof, relayerAddress, HeaderOrCrossChainMsg)
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

type NodeManager struct {
	mcSdk  *MultiChainSdk
	native *NativeContract
}

func (this *NodeManager) NewRegisterCandidateTransaction(peerPubkey string, address []byte) (*types.Transaction, error) {
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
func (this *NodeManager) RegisterCandidate(peerPubkey string, address []byte, signer *Account) (common.Uint256, error) {
	tx, err := this.NewRegisterCandidateTransaction(peerPubkey, address)
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
	state := &node_manager.RegisterPeerParam{
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
	state := &node_manager.RegisterPeerParam{
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

func (this *RelayerManager) NewRegisterRelayerTransaction(address []byte) (*types.Transaction, error) {
	state := &relayer_manager.RelayerParam{
		Address: address,
	}

	sink := new(common.ZeroCopySink)
	state.Serialization(sink)

	return this.native.NewNativeInvokeTransaction(
		TX_VERSION,
		RelayerManagerContractAddress,
		relayer_manager.REGISTER_RELAYER,
		sink.Bytes())
}
func (this *RelayerManager) RegisterRelayer(address []byte, signers []*Account) (common.Uint256, error) {
	tx, err := this.NewRegisterRelayerTransaction(address)
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

func (this *RelayerManager) NewRemoveRelayerTransaction(address []byte) (*types.Transaction, error) {
	state := &relayer_manager.RelayerParam{
		Address: address,
	}

	sink := new(common.ZeroCopySink)
	state.Serialization(sink)

	return this.native.NewNativeInvokeTransaction(
		TX_VERSION,
		RelayerManagerContractAddress,
		relayer_manager.REMOVE_RELAYER,
		sink.Bytes())
}
func (this *RelayerManager) RemoveRelayer(address []byte, signers []*Account) (common.Uint256, error) {
	tx, err := this.NewRemoveRelayerTransaction(address)
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
