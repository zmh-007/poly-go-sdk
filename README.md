# Go SDK For Poly

-   [Go SDK For Poly](#go-sdk-for-poly)
    -   [1. Overview](#overview)
    -   [2. How to use?](#how-to-use)
        -   [2.1 Block Chain API](#block-chain-api)
            -   [2.1.1 Get current block height](#get-current-block-height)
            -   [2.1.2 Get current block hash](#get-current-block-hash)
            -   [2.1.3 Get block by height](#get-block-by-height)
            -   [2.1.4 Get block by hash](#get-block-by-hash)
            -   [2.1.5 Get transaction by transaction hash](#get-transaction-by-transaction-hash)
            -   [2.1.6 Get block hash by block height](#get-block-hash-by-block-height)
            -   [2.1.7 Get block height by transaction hash](#get-block-height-by-transaction-hash)
            -   [2.1.8 Get transaction hashes of block by block height](#get-transaction-hashes-of-block-by-block-height)
            -   [2.1.9 Get storage value of smart contract key](#get-storage-value-of-smart-contract-key)
            -   [2.1.10 Get smart contract by contract address](#get-smart-contract-by-contract-address)
            -   [2.1.11 Get smart contract event by transaction hash](#get-smart-contract-event-by-transaction-hash)
            -   [2.1.12 Get all of smart contract events of block by block height](#get-all-of-smart-contract-events-of-block-by-block-height)
            -   [2.1.13 Get block merkle proof by transaction hash](#get-block-merkle-proof-by-transaction-hash)
            -   [2.1.14 Get transaction state of transaction pool](#get-transaction-state-of-transaction-pool)
            -   [2.1.15 Get transaction count in transaction pool](#get-transaction-count-in-transaction-pool)
            -   [2.1.16 Get version of Poly](#get-version-of-poly)
            -   [2.1.17 Get network id of Poly](#get-network-id-of-poly)
            -   [2.1.18 Send transaction to Poly](#send-transaction-to-poly)
            -   [2.19 Prepare execute transaction](#prepare-execute-transaction)
        -   [2.2 Wallet API](#wallet-api)
            -   [2.2.1 Create or Open Wallet](#create-or-open-wallet)
            -   [2.2.2 Save Wallet](#save-wallet)
            -   [2.2.3 New account](#new-account)
            -   [2.2.4 New default setting account](#new-default-setting-account)
            -   [2.2.5 New account from wif private key](#new-account-from-wif-private-key)
            -   [2.2.5 Delete account](#delete-account)
            -   [2.2.5 Get default account](#get-default-account)
            -   [2.2.6 Set default account](#set-default-account)
            -   [2.2.7 Get account by address](#get-account-by-address)
            -   [2.2.8 Get account by label](#get-account-by-label)
            -   [2.2.9 Get account by index](#get-account-by-index)
            -   [2.2.10 Get account count of wallet](#get-account-count-of-wallet)
            -   [2.2.11 Get default account data](#get-default-account-data)
            -   [2.2.12 Get account data by address](#get-account-data-by-address)
            -   [2.2.13 Get account data by label](#get-account-data-by-label)
            -   [2.2.14 Get account data by index](#get-account-data-by-index)
            -   [2.2.15 Set account label](#set-account-label)
            -   [2.2.16 Set signature scheme of account](#set-signature-scheme-of-account)
            -   [2.2.17 Change account password](#change-account-password)
            -   [2.2.18 Import account to wallet](#import-account-to-wallet)
            -   [2.2.19 Export account to a new wallet](#export-account-to-a-new-wallet)
        -   [2.3 CrossChain API](#crosschain-api)
            -   [2.3.1 Commit crosschain transaction proof of sidechain to Poly](#commit-crosschain-transaction-proof-of-sidechain-to-poly)
            -   [2.3.2 Register a sidechain to Poly](#register-a-sidechain-to-poly)
            -   [2.3.3 Approve the sidechain registration](#approve-the-sidechain-registration)
            -   [2.3.4 Update sidechain information on Poly](#update-sidechain-information-on-poly)
            -   [2.3.5 Approve the update of sidechain information](#approve-the-update-of-sidechain-information)
            -   [2.3.6 Make a proposal to remove side chain](#make-a-proposal-to-remove-side-chain)
            -   [2.3.7 Approve the proposal to remove side chain](#approve-the-proposal-to-remove-side-chain)
            -   [2.3.8 Register the redeem script for BTC vendor](#register-the-redeem-script-for-btc-vendor)
            -   [2.3.9 Set parameters for vendor's BTC-unlocking transactions](#set-parameters-for-vendors-btc-unlocking-transactions)
            -   [2.3.10 Register candidate for new consensus epoch](#register-candidate-for-new-consensus-epoch)
            -   [2.3.11 Approve registration of candidate](#approve-registration-of-candidate)
            -   [2.3.12 Cancel the registration of candidate](#cancel-the-registration-of-candidate)
            -   [2.3.13 Regect the registration of candidate](#regect-the-registration-of-candidate)
            -   [2.3.14 Pull a node into black list](#pull-a-node-into-black-list)
            -   [2.3.15 Pull a node out of black list](#pull-a-node-out-of-black-list)
            -   [2.3.16 Update poly consensus configuration](#update-poly-consensus-configuration)
            -   [2.3.17 Register a wallet as relayer](#register-a-wallet-as-relayer)
            -   [2.3.18 Approve registration of a relayer](#approve-registration-of-a-relayer)
            -   [2.3.19 Remove an account from relayer list](#remove-an-account-from-relayer-list)
            -   [2.3.20 Approve the remove of a relayer](#approve-the-remove-of-a-relayer)
            -   [2.3.21 Commit Dpos to switch consensus epoch](#commit-dpos-to-switch-consensus-epoch)
-   [Contributing](#contributing)
    -   [Website](#website)
    -   [License](#license)

## 1. Overview

This is a comprehensive Go library for the Poly blockchain. Currently, it supports local wallet management, deployment/invoking of smart contracts and communication with the Poly Blockchain. In the future it will also support more rich functions and applications.

## 2. How to use?

First, create an `PolySDK` instance with the `NewPolySdk` method.

    polySdk := NewPolySdk()

Next, create an rpc, rest or websocket client.

    polySdk.NewRpcClient().SetAddress("http://localhost:20336")

Then, call the rpc server through the sdk instance.

### 2.1 Block Chain API

#### 2.1.1 Get current block height

    polySdk.GetCurrentBlockHeight() (uint32, error)

#### 2.1.2 Get current block hash

    polySdk.GetCurrentBlockHash() (common.Uint256, error)

#### 2.1.3 Get block by height

    polySdk.GetBlockByHeight(height uint32) (*types.Block, error)

#### 2.1.4 Get block by hash

    polySdk.GetBlockByHash(blockHash string) (*types.Block, error)

#### 2.1.5 Get transaction by transaction hash

    polySdk.GetTransaction(txHash string) (*types.Transaction, error)

#### 2.1.6 Get block hash by block height

    polySdk.GetBlockHash(height uint32) (common.Uint256, error)

#### 2.1.7 Get block height by transaction hash

    polySdk.GetBlockHeightByTxHash(txHash string) (uint32, error)

#### 2.1.8 Get transaction hashes of block by block height

    polySdk.GetBlockTxHashesByHeight(height uint32) (*sdkcom.BlockTxHashes, error)

#### 2.1.9 Get storage value of smart contract key

    polySdk.GetStorage(contractAddress string, key []byte) ([]byte, error)

#### 2.1.10 Get smart contract by contract address

    polySdk.GetSmartContract(contractAddress string) (*sdkcom.SmartContract, error)

#### 2.1.11 Get smart contract event by transaction hash

    polySdk.GetSmartContractEvent(txHash string) (*sdkcom.SmartContactEvent, error)

#### 2.1.12 Get all of smart contract events of block by block height

    polySdk.GetSmartContractEventByHeight(height uint32) ([]*sdkcom.SmartContactEvent, error)

#### 2.1.13 Get block merkle proof by transaction hash

    polySdk.GetMerkleProof(txHash string) (*sdkcom.MerkleProof, error)

#### 2.1.14 Get transaction state of transaction pool

    polySdk.GetMemPoolTxState(txHash string) (*sdkcom.MemPoolTxState, error)

#### 2.1.15 Get transaction count in transaction pool

    polySdk.GetMemPoolTxCount() (*sdkcom.MemPoolTxCount, error)

#### 2.1.16 Get version of Poly

    polySdk.GetVersion() (string, error)

#### 2.1.17 Get network id of Poly

    polySdk.GetNetworkId() (uint32, error)

#### 2.1.18 Send transaction to Poly

    polySdk.SendTransaction(mutTx *types.MutableTransaction) (common.Uint256, error)

#### 2.19 Prepare execute transaction

    polySdk.PreExecTransaction(mutTx *types.MutableTransaction) (*sdkcom.PreExecResult, error)

### 2.2 Wallet API

#### 2.2.1 Create or Open Wallet

    wa, err := OpenWallet(path string) (*Wallet, error)

If the path is for an existing wallet file, then open the wallet,
otherwise return error.

#### 2.2.2 Save Wallet

    wa.Save() error

Note that any modifications of the wallet require calling `Save()` in
order for the changes to persist.

#### 2.2.3 New account

    wa.NewAccount(keyType keypair.KeyType, curveCode byte, sigScheme s.SignatureScheme, passwd []byte) (*Account, error)

Poly supports three type of keys: ecdsa, sm2 and ed25519, and support
224, 256, 384, 521 bits length of key in ecdsa, but only support 256
bits length of key in sm2 and ed25519.

Poly support multiple signature scheme.

For ECDSA support SHA224withECDSA, SHA256withECDSA, SHA384withECDSA,
SHA512withEdDSA, SHA3-224withECDSA, SHA3-256withECDSA,
SHA3-384withECDSA, SHA3-512withECDSA, RIPEMD160withECDSA;

For SM2 support SM3withSM2, and for SHA512withEdDSA.

#### 2.2.4 New default setting account

    wa.NewDefaultSettingAccount(passwd []byte) (*Account, error)

The default settings for an account uses ECDSA with SHA256withECDSA as
signature scheme.

#### 2.2.5 New account from wif private key

    wa.NewAccountFromWIF(wif, passwd []byte) (*Account, error)

#### 2.2.5 Delete account

    wa.DeleteAccount(address string) error

#### 2.2.5 Get default account

    wa.GetDefaultAccount(passwd []byte) (*Account, error)

#### 2.2.6 Set default account

    wa.SetDefaultAccount(address string) error

#### 2.2.7 Get account by address

    wa.GetAccountByAddress(address string, passwd []byte) (*Account, error)

#### 2.2.8 Get account by label

    wa.GetAccountByLabel(label string, passwd []byte) (*Account, error)

#### 2.2.9 Get account by index

    wa.GetAccountByIndex(index int, passwd []byte) (*Account, error)

Note that indexes start from 1.

#### 2.2.10 Get account count of wallet

    wa.GetAccountCount() int

#### 2.2.11 Get default account data

    wa.GetDefaultAccountData() (*AccountData, error)

#### 2.2.12 Get account data by address

    wa.GetAccountDataByAddress(address string) (*AccountData, error)

#### 2.2.13 Get account data by label

    wa.GetAccountDataByLabel(label string) (*AccountData, error)

#### 2.2.14 Get account data by index

    wa.GetAccountDataByIndex(index int) (*AccountData, error)

Note that indexes start from 1.

#### 2.2.15 Set account label

    wa.SetLabel(address, newLabel string) error

Note that label cannot duplicate.

#### 2.2.16 Set signature scheme of account

    wa.SetSigScheme(address string, sigScheme s.SignatureScheme) error

#### 2.2.17 Change account password

    wa.ChangeAccountPassword(address string, oldPassword, newPassword []byte) error

#### 2.2.18 Import account to wallet

    wa.ImportAccounts(accountDatas []*AccountData, passwds [][]byte) error

#### 2.2.19 Export account to a new wallet

    wa.ExportAccounts(path string, accountDatas []*AccountData, passwds [][]byte, newScrypts ...*keypair.ScryptParam) (*Wallet, error)

### 2.3 CrossChain API

#### 2.3.1 Commit crosschain transaction proof of sidechain to Poly

    polySdk.Native.Ccm.ImportOuterTransfer(sourceChainId uint64, txData []byte, height uint32, proof []byte, relayerAddress []byte, HeaderOrCrossChainMsg []byte, signer *Account) (common.Uint256, error)

#### 2.3.2 Register a sidechain to Poly

    polySdk.Native.Scm.RegisterSideChain(address common.Address, chainId, router uint64, name string,
        blocksToWait uint64, CMCCAddress []byte, signer *Account) (common.Uint256, error) 

#### 2.3.3 Approve the sidechain registration

    polySdk.Native.Scm.ApproveRegisterSideChain(chainId uint64, signer *Account) (common.Uint256, error)

#### 2.3.4 Update sidechain information on Poly

    polySdk.Native.Scm.UpdateSideChain(address common.Address, chainId, router uint64, name string,
        blocksToWait uint64, CMCCAddress []byte, signer *Account) (common.Uint256, error)

#### 2.3.5 Approve the update of sidechain information

    polySdk.Native.Scm.ApproveUpdateSideChain(chainId uint64, signer *Account) (common.Uint256, error)

#### 2.3.6 Make a proposal to remove side chain

    polySdk.Native.Scm.QuitSideChain(chainId uint64, signer *Account) (common.Uint256, error) 

#### 2.3.7 Approve the proposal to remove side chain

    polySdk.Native.Scm.ApproveQuitSideChain(chainId uint64, signer *Account) (common.Uint256, error) 

#### 2.3.8 Register the redeem script for BTC vendor

    polySdk.Native.Scm.RegisterRedeem(redeemChainID, contractChainID uint64, redeem, contractAddress []byte, cVersion uint64, signs [][]byte, signer *Account) (common.Uint256, error)

#### 2.3.9 Set parameters for vendor's BTC-unlocking transactions

    polySdk.Native.Scm.SetBtcTxParam(redeem []byte, redeemId, feeRate, minChange, pver uint64, sigArr [][]byte, signer *Account) (common.Uint256, error) 

#### 2.3.10 Register candidate for new consensus epoch

    polySdk.Native.Nm.RegisterCandidate(peerPubkey string, signer *Account) (common.Uint256, error)

#### 2.3.11 Approve registration of candidate

    polySdk.Native.Nm.ApproveCandidate(peerPubkey string, signer *Account) (common.Uint256, error)

#### 2.3.12 Cancel the registration of candidate

    polySdk.Native.Nm.UnRegisterCandidate(peerPubkey string, signer *Account) (common.Uint256, error)

#### 2.3.13 Regect the registration of candidate

    polySdk.Native.Nm.RejectCandidate(peerPubkey string, signer *Account) (common.Uint256, error)

#### 2.3.14 Pull a node into black list

    polySdk.Native.Nm.BlackNode(peerPubkeyList []string, signer *Account) (common.Uint256, error)

#### 2.3.15 Pull a node out of black list

    polySdk.Native.Nm.WhiteNode(peerPubkey string, signer *Account) (common.Uint256, error)

#### 2.3.16 Update poly consensus configuration

    polySdk.Native.Nm.UpdateConfig(blockMsgDelay, hashMsgDelay, peerHandshakeTimeout, maxBlockChangeView uint32, signers []*Account) (common.Uint256, error)

#### 2.3.17 Register a wallet as relayer

    polySdk.Native.Rm.RegisterRelayer(addressList []common.Address, signer *Account) (common.Uint256, error)

#### 2.3.18 Approve registration of a relayer

    polySdk.Native.Rm.ApproveRegisterRelayer(applyID uint64, signer *Account) (common.Uint256, error)

#### 2.3.19 Remove an account from relayer list

    polySdk.Native.Rm.RemoveRelayer(addressList []common.Address, signer *Account) (common.Uint256, error)

#### 2.3.20 Approve the remove of a relayer

    polySdk.Native.Rm.ApproveRemoveRelayer(removeID uint64, signer *Account) (common.Uint256, error)

#### 2.3.21 Commit Dpos to switch consensus epoch

    polySdk.Native.Nm.CommitDpos(signers []*Account) (common.Uint256, error) 

Contributing
============

Can I contribute patches to the Poly project?

Yes! We appreciate your help!

Please open a pull request with signed-off commits. This means adding a line that says "Signed-off-by: Name <email>" at the end of each commit, indicating that you wrote the code and have the right to pass it on as an open source patch. If you don't sign off your patches, we will not accept them. 

You can also send your patches as emails to the developer mailing list. Please join the Poly mailing list or forum and talk to us about it.

Also, please write good git commit messages. A good commit message looks like this:

Header line: explain the commit in one line

The body of the commit message should be a few lines of text, explaining things in more detail, possibly giving some background about the issue being fixed, etc. 

The body of the commit message can be several paragraphs long, and should use proper word-wrapping and keep the columns shorter than about 74 characters or so. That way "git log" will show things nicely even when it's indented.

Make sure you explain your solution and why you're doing what you're doing, and not just what you're doing. Reviewers (and your future self) can read the patch, but might not understand why a particular solution was implemented.

Reported-by: whoever-reported-it Signed-off-by: Your Name
<youremail@yourhost.com>

Website
-------

-   https://www.poly.network/

License
-------

The Poly library (i.e. all of the code outside of the cmd directory) is licensed under the GNU Lesser General Public License v3.0, also included in our repository in the License file.
