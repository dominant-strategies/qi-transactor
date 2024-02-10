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

func (transactor Transactor) makeUTXOTransaction(outpointHash common.Hash, outpointIndex uint32, from common.Address, to common.Address, btcecKey *secp256k1.PrivateKey, pubKey []byte) *types.Transaction {
	// key = hash(blockHash, index)
	// Find hash / index for originUtxo / imagine this is block hash
	prevOut := *types.NewOutPoint(&outpointHash, outpointIndex)

	in := types.TxIn{
		PreviousOutPoint: prevOut,
		PubKey:           pubKey,
	}

	newOut := types.TxOut{
		Denomination: uint8(0),
		Address:      from.Bytes(),
	}

	utxo := &types.UtxoTx{
		ChainID: big.NewInt(1337),
		TxIn:    []types.TxIn{in},
		TxOut:   []types.TxOut{newOut},
	}

	tx := types.NewTx(utxo)

	chainId := big.NewInt(1337)
	signer := types.NewSigner(chainId, location)

	txHash := signer.Hash(tx)

	sig, err := schnorr.Sign(btcecKey, txHash[:])
	if err != nil {
		log.Fatalf("Failed to sign transaction: %v", err)
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
	for {
		txMutex.Lock()
		for address, outpoints := range spendableOutpoints {
			// check if address is in addressMap
			if addressMap[address].PrivateKey == nil {
				continue
			}
			fromPrivateKey := addressMap[address].PrivateKey // Assuming addressMap holds the private keys
			fromAddress := common.HexToAddress(address, location)
			// get random address from addressMap
			randIndex := rand.Intn(len(addressMap))
			i := 0
			var toAddressStr string
			for key := range addressMap {
				if i == randIndex {
					toAddressStr = key
					break
				}
				i++
			}
			toAddress := common.HexToAddress(toAddressStr, location)
			for _, item := range outpoints {
				// Assuming toAddress is defined earlier or you have a way to determine it
				transactor.makeUTXOTransaction(item.outpoint.Hash, item.outpoint.Index, fromAddress, toAddress, fromPrivateKey, fromPrivateKey.PubKey().SerializeUncompressed())
				// After processing an outpoint for an address, you might want to remove it or mark it as spent
			}
			// Clear the processed outpoints for this address
			spendableOutpoints[address] = nil
		}
		txMutex.Unlock()
		time.Sleep(1 * time.Second) // Sleep to rate limit transaction creation
	}
}
