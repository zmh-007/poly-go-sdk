/*
* Copyright (C) 2020 The poly network Authors
* This file is part of The poly network library.
*
* The poly network is free software: you can redistribute it and/or modify
* it under the terms of the GNU Lesser General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
*
* The poly network is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
* GNU Lesser General Public License for more details.
* You should have received a copy of the GNU Lesser General Public License
* along with The poly network . If not, see <http://www.gnu.org/licenses/>.
 */
package poly_go_sdk

import (
	"fmt"

	"github.com/ontio/ontology-crypto/keypair"
	sdkcom "github.com/polynetwork/poly-go-sdk/common"
	"github.com/polynetwork/poly/common"
	"github.com/polynetwork/poly/core/types"
	ccm "github.com/polynetwork/poly/native/service/cross_chain_manager"
	nccmc "github.com/polynetwork/poly/native/service/cross_chain_manager/common"
	"github.com/polynetwork/poly/native/service/governance/neo3_state_manager"
	"github.com/polynetwork/poly/native/service/governance/node_manager"
	"github.com/polynetwork/poly/native/service/governance/relayer_manager"
	"github.com/polynetwork/poly/native/service/governance/side_chain_manager"
	hs "github.com/polynetwork/poly/native/service/header_sync"
	hsc "github.com/polynetwork/poly/native/service/header_sync/common"
	mcnsu "github.com/polynetwork/poly/native/service/utils"
	"github.com/polynetwork/poly/native/states"
)

var (
	HeaderSyncContractAddress        = mcnsu.HeaderSyncContractAddress
	CrossChainManagerContractAddress = mcnsu.CrossChainManagerContractAddress
	SideChainManagerContractAddress  = mcnsu.SideChainManagerContractAddress
	NodeManagerContractAddress       = mcnsu.NodeManagerContractAddress
	RelayerManagerContractAddress    = mcnsu.RelayerManagerContractAddress
	Neo3StateManagerContractAddress  = mcnsu.Neo3StateManagerContractAddress
)

var (
	TX_VERSION = byte(0)
)

var OPCODE_IN_PAYLOAD = map[byte]bool{0xc6: true, 0x6b: true, 0x6a: true, 0xc8: true, 0x6c: true, 0x68: true, 0x67: true,
	0x7c: true, 0xc1: true}

type NativeContract struct {
	mcSdk *PolySdk
	Hs    *HeaderSync
	Ccm   *CrossChainManager
	Scm   *SideChainManager
	Nm    *NodeManager
	Rm    *RelayerManager
	Sm    *StateManager
}

func newNativeContract(mcSdk *PolySdk) *NativeContract {
	native := &NativeContract{mcSdk: mcSdk}
	native.Hs = &HeaderSync{native: native, mcSdk: mcSdk}
	native.Ccm = &CrossChainManager{native: native, mcSdk: mcSdk}
	native.Scm = &SideChainManager{native: native, mcSdk: mcSdk}
	native.Nm = &NodeManager{native: native, mcSdk: mcSdk}
	native.Rm = &RelayerManager{native: native, mcSdk: mcSdk}
	native.Sm = &StateManager{native: native, mcSdk: mcSdk}
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

	return this.mcSdk.NewInvokeTransaction(invokeCode.Bytes())
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

type CrossChainManager struct {
	mcSdk  *PolySdk
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

func (this *CrossChainManager) NewBlackChainTransaction(chainID uint64) (*types.Transaction, error) {
	state := &ccm.BlackChainParam{
		ChainID: chainID,
	}

	sink := new(common.ZeroCopySink)
	state.Serialization(sink)

	return this.native.NewNativeInvokeTransaction(
		TX_VERSION,
		CrossChainManagerContractAddress,
		ccm.BLACK_CHAIN,
		sink.Bytes())
}

func (this *CrossChainManager) BlackChain(chainID uint64, signers []*Account) (common.Uint256, error) {
	tx, err := this.NewBlackChainTransaction(chainID)
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

func (this *CrossChainManager) NewWhiteChainTransaction(chainID uint64) (*types.Transaction, error) {
	state := &ccm.BlackChainParam{
		ChainID: chainID,
	}

	sink := new(common.ZeroCopySink)
	state.Serialization(sink)

	return this.native.NewNativeInvokeTransaction(
		TX_VERSION,
		CrossChainManagerContractAddress,
		ccm.WHITE_CHAIN,
		sink.Bytes())
}

func (this *CrossChainManager) WhiteChain(chainID uint64, signers []*Account) (common.Uint256, error) {
	tx, err := this.NewWhiteChainTransaction(chainID)
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

type HeaderSync struct {
	mcSdk  *PolySdk
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
	mcSdk  *PolySdk
	native *NativeContract
}

func (this *SideChainManager) NewRegisterSideChainTransaction(address common.Address, chainId, router uint64,
	name string, blocksToWait uint64, CMCCAddress []byte) (*types.Transaction, error) {
	return this.NewRegisterSideChainTransactionExt(address, chainId, router, name, blocksToWait, CMCCAddress, nil)
}

func (this *SideChainManager) NewRegisterSideChainTransactionExt(address common.Address, chainId, router uint64,
	name string, blocksToWait uint64, CMCCAddress, extraInfo []byte) (*types.Transaction, error) {
	state := &side_chain_manager.RegisterSideChainParam{
		Address:      address,
		ChainId:      chainId,
		Router:       router,
		Name:         name,
		BlocksToWait: blocksToWait,
		CCMCAddress:  CMCCAddress,
		ExtraInfo:    extraInfo,
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

func (this *SideChainManager) RegisterSideChainExt(address common.Address, chainId, router uint64, name string,
	blocksToWait uint64, CMCCAddress, extraInfo []byte, signer *Account) (common.Uint256, error) {
	tx, err := this.NewRegisterSideChainTransactionExt(address, chainId, router, name, blocksToWait, CMCCAddress, extraInfo)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	err = this.mcSdk.SignToTransaction(tx, signer)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	return this.mcSdk.SendTransaction(tx)
}

func (this *SideChainManager) RegisterSideChain(address common.Address, chainId, router uint64, name string,
	blocksToWait uint64, CMCCAddress []byte, signer *Account) (common.Uint256, error) {
	return this.RegisterSideChainExt(address, chainId, router, name, blocksToWait, CMCCAddress, nil, signer)
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

func (this *SideChainManager) NewUpdateSideChainTransaction(address common.Address, chainId, router uint64, name string,
	blocksToWait uint64, CMCCAddress []byte) (*types.Transaction, error) {
	return this.NewUpdateSideChainTransactionExt(address, chainId, router, name, blocksToWait, CMCCAddress, nil)
}

func (this *SideChainManager) NewUpdateSideChainTransactionExt(address common.Address, chainId, router uint64, name string,
	blocksToWait uint64, CMCCAddress []byte, extraInfo []byte) (*types.Transaction, error) {
	state := &side_chain_manager.RegisterSideChainParam{
		Address:      address,
		ChainId:      chainId,
		Router:       router,
		Name:         name,
		BlocksToWait: blocksToWait,
		CCMCAddress:  CMCCAddress,
		ExtraInfo:    extraInfo,
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

func (this *SideChainManager) UpdateSideChainExt(address common.Address, chainId, router uint64, name string,
	blocksToWait uint64, CMCCAddress []byte, extraInfo []byte, signer *Account) (common.Uint256, error) {
	tx, err := this.NewUpdateSideChainTransactionExt(address, chainId, router, name, blocksToWait, CMCCAddress, extraInfo)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	err = this.mcSdk.SignToTransaction(tx, signer)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	return this.mcSdk.SendTransaction(tx)
}

func (this *SideChainManager) UpdateSideChain(address common.Address, chainId, router uint64, name string,
	blocksToWait uint64, CMCCAddress []byte, signer *Account) (common.Uint256, error) {
	return this.UpdateSideChainExt(address, chainId, router, name, blocksToWait, CMCCAddress, nil, signer)
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
	tx, err := this.NewApproveQuitSideChainTransaction(chainId, signer.Address)
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

func (this *SideChainManager) NewSetBtcTxParamTransaction(redeem []byte, redeemId, feeRate, minChange, pver uint64, sigArr [][]byte) (*types.Transaction, error) {
	state := &side_chain_manager.BtcTxParam{
		Detial: &side_chain_manager.BtcTxParamDetial{
			MinChange: minChange,
			FeeRate:   feeRate,
			PVersion:  pver,
		},
		Sigs:          sigArr,
		RedeemChainId: redeemId,
		Redeem:        redeem,
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
	mcSdk  *PolySdk
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
	state := &node_manager.PeerParam{
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
	state := &node_manager.PeerParam{
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
	mcSdk  *PolySdk
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

type StateManager struct {
	mcSdk  *PolySdk
	native *NativeContract
}

func (this *StateManager) NewRegisterStateValidatorTransaction(pubKeys []string, address common.Address) (*types.Transaction, error) {
	state := &neo3_state_manager.StateValidatorListParam{
		StateValidators: pubKeys,
		Address:         address,
	}

	sink := new(common.ZeroCopySink)
	state.Serialization(sink)

	return this.native.NewNativeInvokeTransaction(
		TX_VERSION,
		Neo3StateManagerContractAddress,
		neo3_state_manager.REGISTER_STATE_VALIDATOR,
		sink.Bytes())
}

func (this *StateManager) RegisterStateValidator(pubKeys []string, signer *Account) (common.Uint256, error) {
	tx, err := this.NewRegisterStateValidatorTransaction(pubKeys, signer.Address)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	err = this.mcSdk.SignToTransaction(tx, signer)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	return this.mcSdk.SendTransaction(tx)
}

func (this *StateManager) NewApproveRegisterStateValidatorTransaction(applyID uint64, address common.Address) (*types.Transaction, error) {
	state := &neo3_state_manager.ApproveStateValidatorParam{
		ID:      applyID,
		Address: address,
	}

	sink := new(common.ZeroCopySink)
	state.Serialization(sink)

	return this.native.NewNativeInvokeTransaction(
		TX_VERSION,
		Neo3StateManagerContractAddress,
		neo3_state_manager.APPROVE_REGISTER_STATE_VALIDATOR,
		sink.Bytes())
}

func (this *StateManager) ApproveRegisterStateValidator(applyID uint64, signer *Account) (common.Uint256, error) {
	tx, err := this.NewApproveRegisterStateValidatorTransaction(applyID, signer.Address)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	err = this.mcSdk.SignToTransaction(tx, signer)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	return this.mcSdk.SendTransaction(tx)
}

func (this *StateManager) NewRemoveStateValidatorTransaction(pubKeys []string, address common.Address) (*types.Transaction, error) {
	state := &neo3_state_manager.StateValidatorListParam{
		StateValidators: pubKeys,
		Address:         address,
	}

	sink := new(common.ZeroCopySink)
	state.Serialization(sink)

	return this.native.NewNativeInvokeTransaction(
		TX_VERSION,
		Neo3StateManagerContractAddress,
		neo3_state_manager.REMOVE_STATE_VALIDATOR,
		sink.Bytes())
}

func (this *StateManager) RemoveStateValidator(pubKeys []string, signer *Account) (common.Uint256, error) {
	tx, err := this.NewRemoveStateValidatorTransaction(pubKeys, signer.Address)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	err = this.mcSdk.SignToTransaction(tx, signer)
	if err != nil {
		return common.UINT256_EMPTY, err
	}
	return this.mcSdk.SendTransaction(tx)
}

func (this *StateManager) NewApproveRemoveStateValidatorTransaction(removeID uint64, address common.Address) (*types.Transaction, error) {
	state := &neo3_state_manager.ApproveStateValidatorParam{
		ID:      removeID,
		Address: address,
	}

	sink := new(common.ZeroCopySink)
	state.Serialization(sink)

	return this.native.NewNativeInvokeTransaction(
		TX_VERSION,
		Neo3StateManagerContractAddress,
		neo3_state_manager.APPROVE_REMOVE_STATE_VALIDATOR,
		sink.Bytes())
}

func (this *StateManager) ApproveRemoveStateValidator(removeID uint64, signer *Account) (common.Uint256, error) {
	tx, err := this.NewApproveRemoveStateValidatorTransaction(removeID, signer.Address)
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
