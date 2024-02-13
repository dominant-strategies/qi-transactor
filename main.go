package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"math/rand"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcec/v2/schnorr/musig2"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/dominant-strategies/go-quai/common"
	"github.com/dominant-strategies/go-quai/core/types"
	"github.com/dominant-strategies/go-quai/crypto"
	"github.com/dominant-strategies/go-quai/quaiclient/ethclient"
)

const wsUrl = "ws://localhost:8003"

var location = common.Location{0, 0}

type AddressInfo struct {
	Address    string
	Index      int
	Path       string
	PrivateKey string
}

// New struct to hold JSON file structure
type Allocation struct {
	Groups map[string]map[string][]AddressInfo
}

type AddressData struct {
	PrivateKey *secp256k1.PrivateKey // Map address to private key
	Balance    *big.Int
	Location   common.Location
}

var (
	addressMap         map[string]AddressData        // Map address to balance and location
	spendableOutpoints map[string][]OutpointAndTxOut // Map address to spendable outpoints
	txMutex            sync.Mutex
)

type GenesisUTXO struct {
	Denomination int    `json:"denomination"`
	Index        int    `json:"index"`
	Hash         string `json:"hash"`
}

type OutpointAndTxOut struct {
	outpoint *types.OutPoint
	txOut    *types.TxOut
}

const maxBlocks = 100

var (
	headerHashes []common.Hash
	hashMutex    sync.Mutex
	blockInfos   []blockInfo // Slice to store information about the last 100 blocks
)

type blockInfo struct {
	Time             time.Time
	TransactionCount int
}

var txTotal = 0

type Transactor struct {
	client *ethclient.Client
}

func main() {
	// Initialize maps
	addressMap = make(map[string]AddressData)
	spendableOutpoints = make(map[string][]OutpointAndTxOut)

	wsClient, err := ethclient.Dial(wsUrl)
	if err != nil {
		log.Fatalf("Failed to connect to the Ethereum WebSocket client: %v", err)
	}
	defer wsClient.Close()

	transactor := Transactor{
		client: wsClient,
	}

	// Load addresses and private keys from JSON file
	err = transactor.loadAddresses("gen_alloc_keys.json", "group-0")
	if err != nil {
		log.Fatalf("Error loading addresses: %v", err)
	}

	err = transactor.loadGenesisUtxos("gen_alloc_qi_cyprus1.json")
	if err != nil {
		log.Fatalf("Error loading genesis UTXOs: %v", err)
	}

	go transactor.listenForNewBlocks()
	go transactor.createTransactions()

	// Wait for an interrupt signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	fmt.Println("Shutting down...")
	// Perform any cleanup if necessary
}

// Load addresses and private keys from a specified group in the JSON file
func (transactor Transactor) loadAddresses(filename, groupName string) error {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return err
	}

	var alloc Allocation
	if err := json.Unmarshal(data, &alloc); err != nil {
		return err
	}

	group, exists := alloc.Groups[groupName]
	if !exists {
		return fmt.Errorf("group %s does not exist", groupName)
	}

	for _, zones := range group {
		for _, info := range zones {
			privateKey, err := crypto.HexToECDSA(info.PrivateKey[2:]) // Remove '0x' prefix
			if err != nil {
				log.Printf("Invalid private key for address %s: %v", info.Address, err)
				continue
			}
			btcecKey, _ := btcec.PrivKeyFromBytes(privateKey.D.Bytes())
			secpKey := secp256k1.PrivKeyFromBytes(btcecKey.Serialize())

			lowStrAddress := strings.ToLower(info.Address)
			address := common.HexToAddress(info.Address, location)

			balance, err := transactor.client.QiBalance(context.Background(), address)
			if err != nil {
				log.Printf("Failed to get balance for address %s: %v", info.Address, err)
				continue
			}
			fmt.Printf("Address %s, balance %d\n", lowStrAddress, balance)

			s := AddressData{
				PrivateKey: secpKey,
				Balance:    balance,
				Location:   location,
			}
			addressMap[lowStrAddress] = s
			// Initialize spendableOutpoints map for this address
			spendableOutpoints[lowStrAddress] = make([]OutpointAndTxOut, 0)
		}
	}

	return nil
}

func (transactor Transactor) loadGenesisUtxos(filename string) error {
	file, err := ioutil.ReadFile(filename)
	if err != nil {
		return fmt.Errorf("error reading file: %v", err)
	}

	var utxos map[string]GenesisUTXO
	if err := json.Unmarshal(file, &utxos); err != nil {
		return fmt.Errorf("error unmarshalling JSON: %v", err)
	}

	for address, utxo := range utxos {
		hash := common.HexToHash(utxo.Hash)
		outpoint := &types.OutPoint{Hash: hash, Index: uint32(utxo.Index)}
		lowStrAddr := strings.ToLower(address)
		addr := common.Hex2Bytes(lowStrAddr)
		txOut := &types.TxOut{
			Address:      addr,
			Denomination: uint8(utxo.Denomination),
		}
		spendableOutpoints[lowStrAddr] = append(spendableOutpoints[lowStrAddr], OutpointAndTxOut{
			outpoint: outpoint,
			txOut:    txOut,
		})
	}
	return nil
}

func (transactor Transactor) makeUTXOTransaction(ins []types.TxIn, outs []types.TxOut, privKeys []*secp256k1.PrivateKey, pubKeys []*secp256k1.PublicKey) *types.Transaction {
	// key = hash(blockHash, index)
	// Find hash / index for originUtxo / imagine this is block hash

	utxo := &types.UtxoTx{
		ChainID: big.NewInt(1337),
		TxIn:    ins,
		TxOut:   outs,
	}

	tx := types.NewTx(utxo)

	chainId := big.NewInt(1337)

	if len(privKeys) != len(pubKeys) {
		log.Fatal("Private keys and public keys must be the same length")
	}

	signer := types.NewSigner(chainId, location)

	txHash := signer.Hash(tx)

	var sig *schnorr.Signature
	var err error
	if len(privKeys) == 1 {
		sig, err = schnorr.Sign(privKeys[0], txHash[:])
		if err != nil {
			log.Fatalf("Failed to sign transaction: %v", err)
		}
	} else {
		sig, err = getAggSig(privKeys, pubKeys, txHash)
		if err != nil {
			log.Fatalf("Failed to sign transaction: %v", err)
		}
	}

	signedUtxo := &types.UtxoTx{
		ChainID:   big.NewInt(1337),
		TxIn:      tx.TxIn(),
		TxOut:     tx.TxOut(),
		Signature: sig,
	}

	signedTx := types.NewTx(signedUtxo)

	// Send the transaction
	err = transactor.client.SendTransaction(context.Background(), signedTx)
	if err != nil {
		log.Fatalf("Failed to send transaction: %v", err)
	}

	return tx
}

func (transactor Transactor) listenForNewBlocks() {
	// Subscribe to new block headers
	headers := make(chan *types.Header)
	sub, err := transactor.client.SubscribeNewHead(context.Background(), headers)
	if err != nil {
		log.Fatalf("Failed to subscribe to new headers: %v", err)
	}
	defer sub.Unsubscribe()

	// Listen for new blocks
	fmt.Println("Listening for new blocks...")
	for {
		select {
		case err := <-sub.Err():
			log.Fatal(err)
		case header := <-headers:
			hashMutex.Lock()
			headerHashes = append(headerHashes, header.Hash())

			time.Sleep(1 * time.Second)
			transactor.getBlockAndTransactions(header.Hash())
			hashMutex.Unlock()
		}
	}
}

func (transactor Transactor) getBlockAndTransactions(hash common.Hash) {
	// Retrieve the block by its hash
	block, err := transactor.client.BlockByHash(context.Background(), hash)
	if err != nil {
		fmt.Printf("Failed to retrieve the block: %s %s\n", hash, err)
		return
	}

	// Display block information
	fmt.Printf("number: %d txs: %d  hash: %s\n", block.Header().NumberArray(), len(block.Transactions()), block.Hash().Hex())

	// Calculate TPS based on block time
	currentBlockInfo := blockInfo{
		Time:             time.Unix(int64(block.Time()), 0),
		TransactionCount: len(block.Transactions()),
	}
	blockInfos = append(blockInfos, currentBlockInfo)
	if len(blockInfos) > maxBlocks {
		blockInfos = blockInfos[1:] // Keep only the last 100 blocks
	}

	// Calculate weighted TPS
	if len(blockInfos) > 1 {
		var totalTransactions int
		var totalTime float64
		for i := 1; i < len(blockInfos); i++ {
			totalTransactions += blockInfos[i].TransactionCount
			totalTime += blockInfos[i].Time.Sub(blockInfos[i-1].Time).Seconds()
		}
		if totalTime > 0 {
			weightedTPS := float64(totalTransactions) / totalTime
			fmt.Printf("Total Transactions: %d Weighted TPS (last %d blocks): %f\n", txTotal, len(blockInfos), weightedTPS)
		}
	}

	// Iterate over and display transactions in the block
	txMutex.Lock()
	defer txMutex.Unlock()

	// coinbaseTx := block.Transactions()[0]
	// coinbaseOuts := coinbaseTx.TxOut()
	// for i := range coinbaseOuts {
	// 	addressStr := "0x" + common.Bytes2Hex(coinbaseOuts[0].Address)

	// 	outpoint := &types.OutPoint{Hash: block.Hash(), Index: uint32(i)}
	// 	outpointAndTxOut := OutpointAndTxOut{outpoint, &coinbaseTx.TxOut()[i]}
	// 	spendableOutpoints[addressStr] = append(spendableOutpoints[addressStr], outpointAndTxOut)
	// 	outpointTotal += 1
	// }
	// txTotal += 1

	for _, tx := range block.Transactions()[1:] {
		for i, txOut := range tx.TxOut() {
			outpoint := &types.OutPoint{Hash: tx.Hash(), Index: uint32(i)}
			addressStr := "0x" + common.Bytes2Hex(txOut.Address)

			// Check if the address is one of the loaded addresses with a private key
			if _, exists := addressMap[addressStr]; exists {
				outpointAndTxOut := OutpointAndTxOut{outpoint, &txOut}
				// Append the outpoint to the spendableOutpoints map for the address
				spendableOutpoints[addressStr] = append(spendableOutpoints[addressStr], outpointAndTxOut)
			}
		}
		txTotal += 1
	}

	// for address, outpoints := range spendableOutpoints {
	// 	if len(outpoints) > 0 {
	// 		fmt.Println("address", address, "current spendable outs", len(outpoints))
	// 	}
	// }
}

func (transactor Transactor) createTransactions() {
	rand.Seed(time.Now().UnixNano()) // Seed the random number generator

	for {
		txMutex.Lock()
		for address, outpoints := range spendableOutpoints {
			if len(outpoints) == 0 || addressMap[address].PrivateKey == nil {
				continue // Skip if no outpoints or no private key
			}

			// Randomly decide between 2 inputs to 1 out or 1 in to 9 outs
			if rand.Intn(2) == 0 && len(outpoints) >= 2 { // 50% chance, and ensure at least 2 outpoints available
				// Case 1: 2 inputs to 1 output
				// Randomly select another outpoint from the same address
				selectedOutpoints := spendableOutpoints[address][:2]

				toAddressStr := getRandomAddress(addressMap)
				toAddress := common.HexToAddress(toAddressStr, location)

				ins, outs, privKeys, pubKeys := createInOutPairsForTransaction(selectedOutpoints, toAddress, addressMap[address].PrivateKey)
				transactor.makeUTXOTransaction(ins, outs, privKeys, pubKeys)

				spendableOutpoints[address] = spendableOutpoints[address][2:] // Remove the first 2 outpoints used
			} else {
				// Case 2: 1 input to 9 outputs
				selectedOutpoint := outpoints[0] // Simplified selection; adjust as needed

				if selectedOutpoint.txOut.Denomination < 2 {
					// fmt.Println("Denomination too low to send to 9 outputs", selectedOutpoint.txOut.Denomination)
					continue
				}
				in := types.TxIn{
					PreviousOutPoint: *types.NewOutPoint(&selectedOutpoint.outpoint.Hash, selectedOutpoint.outpoint.Index),
					PubKey:           addressMap[address].PrivateKey.PubKey().SerializeUncompressed(),
				}

				outs := make([]types.TxOut, 9)
				for i := 0; i < 9; i++ {
					toAddressStr := getRandomAddress(addressMap)
					toAddress := common.HexToAddress(toAddressStr, location)

					outs[i] = types.TxOut{
						Denomination: uint8(0), // Simplified; adjust denomination as needed
						Address:      toAddress.Bytes(),
					}
				}

				privKeys := []*secp256k1.PrivateKey{addressMap[address].PrivateKey}
				pubKeys := []*secp256k1.PublicKey{addressMap[address].PrivateKey.PubKey()}

				transactor.makeUTXOTransaction([]types.TxIn{in}, outs, privKeys, pubKeys)

				spendableOutpoints[address] = spendableOutpoints[address][1:] // Remove the first outpoint used
			}
		}
		txMutex.Unlock()
		time.Sleep(1 * time.Second) // Sleep to rate limit transaction creation
	}
}

// Utility function to get a random address from addressMap, excluding the input address
func getRandomAddress(addressMap map[string]AddressData) string {
	keys := make([]string, 0, len(addressMap))
	for k := range addressMap {
		keys = append(keys, k)
	}
	if len(keys) == 0 {
		return "" // Handle case where addressMap is empty
	}
	randIndex := rand.Intn(len(keys))
	return keys[randIndex]
}

// Simplified function signature for creating input-output pairs; implement according to your actual types and logic
func createInOutPairsForTransaction(outpoints []OutpointAndTxOut, toAddress common.Address, privateKey *secp256k1.PrivateKey) ([]types.TxIn, []types.TxOut, []*secp256k1.PrivateKey, []*secp256k1.PublicKey) {
	var ins []types.TxIn
	var denominations []uint8
	var privKeys []*secp256k1.PrivateKey
	var pubKeys []*secp256k1.PublicKey
	for _, outpoint := range outpoints {
		in := types.TxIn{
			PreviousOutPoint: *types.NewOutPoint(&outpoint.outpoint.Hash, outpoint.outpoint.Index),
			PubKey:           privateKey.PubKey().SerializeUncompressed(),
		}
		ins = append(ins, in)

		denominations = append(denominations, outpoint.txOut.Denomination)
		privKeys = append(privKeys, privateKey)
		pubKeys = append(pubKeys, privateKey.PubKey())
	}

	outs := make([]types.TxOut, 1)
	outs[0] = types.TxOut{
		Denomination: denominations[0],
		Address:      toAddress.Bytes(),
	}

	return ins, outs, privKeys, pubKeys
}

func getAggSig(privKeys []*secp256k1.PrivateKey, pubKeys []*secp256k1.PublicKey, txHash [32]byte) (*schnorr.Signature, error) {
	keys := make([]*btcec.PrivateKey, len(privKeys))
	copy(keys, privKeys)

	signSet := make([]*btcec.PublicKey, len(pubKeys))
	copy(signSet, pubKeys)

	var combinedKey *btcec.PublicKey
	var ctxOpts []musig2.ContextOption

	ctxOpts = append(ctxOpts, musig2.WithKnownSigners(signSet))

	// Now that we have all the signers, we'll make a new context, then
	// generate a new session for each of them(which handles nonce
	// generation).
	signers := make([]*musig2.Session, len(keys))
	for i, signerKey := range keys {
		signCtx, err := musig2.NewContext(
			signerKey, false, ctxOpts...,
		)
		if err != nil {
			log.Fatalf("unable to generate context: %v", err)
		}

		if combinedKey == nil {
			combinedKey, err = signCtx.CombinedKey()
			if err != nil {
				log.Fatalf("combined key not available: %v", err)
			}
		}

		session, err := signCtx.NewSession()
		if err != nil {
			log.Fatalf("unable to generate new session: %v", err)
		}
		signers[i] = session
	}

	// Next, in the pre-signing phase, we'll send all the nonces to each
	// signer.
	var wg sync.WaitGroup
	for i, signCtx := range signers {
		signCtx := signCtx

		wg.Add(1)
		go func(idx int, signer *musig2.Session) {
			defer wg.Done()

			for j, otherCtx := range signers {
				if idx == j {
					continue
				}

				nonce := otherCtx.PublicNonce()
				haveAll, err := signer.RegisterPubNonce(nonce)
				if err != nil {
					log.Fatalf("unable to add public nonce")
				}

				if j == len(signers)-1 && !haveAll {
					log.Fatalf("all public nonces should have been detected")
				}
			}
		}(i, signCtx)
	}

	wg.Wait()

	// In the final step, we'll use the first signer as our combiner, and
	// generate a signature for each signer, and then accumulate that with
	// the combiner.
	combiner := signers[0]
	for i := range signers {
		signer := signers[i]
		partialSig, err := signer.Sign(txHash)
		if err != nil {
			log.Fatalf("unable to generate partial sig: %v", err)
		}

		// We don't need to combine the signature for the very first
		// signer, as it already has that partial signature.
		if i != 0 {
			haveAll, err := combiner.CombineSig(partialSig)
			if err != nil {
				log.Fatalf("unable to combine sigs: %v", err)
			}

			if i == len(signers)-1 && !haveAll {
				log.Fatalf("final sig wasn't reconstructed")
			}
		}
	}

	aggKey, _, _, _ := musig2.AggregateKeys(
		signSet, false,
	)

	if !aggKey.FinalKey.IsEqual(combinedKey) {
		log.Fatalf("aggKey is invalid!")
	}

	// Finally we'll combined all the nonces, and ensure that it validates
	// as a single schnorr signature.
	finalSig := combiner.FinalSig()
	if !finalSig.Verify(txHash[:], combinedKey) {
		log.Fatalf("final sig is invalid!")
	}

	return finalSig, nil
}
