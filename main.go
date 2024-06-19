package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"math/rand"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"flag"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcec/v2/schnorr/musig2"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/dominant-strategies/go-quai/cmd/utils"
	"github.com/dominant-strategies/go-quai/common"
	"github.com/dominant-strategies/go-quai/core/types"
	"github.com/dominant-strategies/go-quai/crypto"
	"github.com/dominant-strategies/go-quai/params"
	"github.com/dominant-strategies/go-quai/quaiclient/ethclient"
	"github.com/spf13/viper"
)

var (
	wsUrl        string
	location     = common.Location{0, 0}
	genAllocPath string
	selectedZone string
	etxZone      string
	chainId      int64
	keysFile     string
	group        string
)

type AddressInfo struct {
	Address    string `json:"address"                     gencodec:"required"`
	Index      int    `json:"index"                     gencodec:"required"`
	Path       string `json:"path"                     gencodec:"required"`
	PrivateKey string `json:"privateKey"                     gencodec:"required"`
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
	addressMap               map[common.AddressBytes]AddressData // Map address to balance and location
	etxAddresses             []common.AddressBytes               // Map address to balance and location
	backupSpendableOutpoints map[common.AddressBytes][]OutpointAndTxOut
	spendableOutpoints       map[common.AddressBytes][]OutpointAndTxOut // Map address to spendable outpoints
	lowDenomOutpoints        map[common.AddressBytes][]OutpointAndTxOut
	txMutex                  sync.Mutex
	numStartingInputs        uint64
	createMaxOutputs         bool
	startTime                time.Time
	totalNumOuts             int
	totalLowDenomOuts        int
	numTxsSent               int
	totalTxCreationTime      = time.Duration(0)
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

const maxBlocks = 50

var (
	headerHashes []common.Hash
	blockInfos   []blockInfo // Slice to store information about the last 50 blocks
)

type blockInfo struct {
	Time             time.Time
	TransactionCount int
}

type ConsolidatedOutpoint struct {
	newInput     types.TxIn
	address      common.AddressBytes
	denomination uint8
}

var MIN_DENOMINATION = uint8(2) // 2 for usual, 13 for testing

type Transactor struct {
	client     *ethclient.Client
	config     Config
	CurrentTPS float64
	TargetTPS  int
}

type Config struct {
	Env             string  `json:"env"`
	BlockTime       int     `json:"blockTime"`
	MachinesRunning int     `json:"machinesRunning"`
	TargetTps       int     `json:"targetTps"`
	BloomTps        int     `json:"bloomTps"`
	Increment       bool    `json:"increment"`
	EtxFreq         float64 `json:"etxFreq"`
	Kp              float64 `json:"kp"` // proportional gain for P controller
	Ki              float64 `json:"ki"` // integral gain for PI controller
	MemPoolMax      int     `json:"memPoolMax"`
	MaxOutputsFreq  float64 `json:"maxOutputsFreq"`
}

func main() {
	var cfg Config

	viper.SetConfigName("config")
	viper.SetConfigType("json")
	viper.AddConfigPath("./config/")
	err := viper.ReadInConfig() // Find and read the config file
	if err != nil {             // Handle errors reading the config file
		panic(fmt.Errorf("fatal error config file: %w", err))
	}
	cfg.Env = viper.GetString("env")
	cfg.BlockTime = viper.GetInt("blockTime")
	cfg.MachinesRunning = viper.GetInt("machinesRunning")
	cfg.TargetTps = viper.GetInt("txs.tps.target")
	cfg.BloomTps = viper.GetInt("txs.tps.bloomTps")
	cfg.Increment = viper.GetBool("txs.tps.increment.enabled")
	cfg.EtxFreq = viper.GetFloat64("txs.etxFreq")
	if cfg.EtxFreq > 0.5 {
		fmt.Println("EtxFreq must be less than or equal to 0.5, setting to 0.5")
		cfg.EtxFreq = 0.5
	}

	cfg.MemPoolMax = viper.GetInt("mempool.max")
	cfg.Kp = viper.GetFloat64("kp")
	cfg.Ki = viper.GetFloat64("ki")
	cfg.MaxOutputsFreq = viper.GetFloat64("txs.maxOutputsFreq")
	if cfg.MaxOutputsFreq > 0.5 {
		fmt.Println("MaxOutputsFreq must be less than or equal to 0.5, setting to 0.5")
		cfg.MaxOutputsFreq = 0.5
	}
	// Now you can use cfg to access the configuration
	fmt.Printf("Environment: %s\n", cfg.Env)
	fmt.Printf("Block Time: %dms\n", cfg.BlockTime)

	// Define a string flag to capture the zone input
	zoneFlag := flag.String("zone", "", "Zone flag to set the wsUrl and location (e.g., zone-0-0, zone-0-1, ... zone-2-2)")
	chainIdFlag := flag.Int64("chain", 1337, "ChainId flag (e.g., 1337)")
	keysFileFlag := flag.String("file", "gen_alloc_qi_keys.json", "File flag to set the genAllocPath (e.g., gen_alloc_qi_keys.json)")
	groupFlag := flag.String("group", "group-0", "Group flag to set the group (e.g., group-0, group-1, ... group-2)")

	// Parse the flags
	flag.Parse()

	// Set wsUrl and location based on the zoneFlag
	switch *zoneFlag {
	case "zone-0-0":
		wsUrl = "ws://127.0.0.1:8200"
		location = common.Location{0, 0}
		genAllocPath = "genallocs/gen_alloc_qi_cyprus1.json"
		etxZone = "zone-1-0"
	case "zone-0-1":
		wsUrl = "ws://127.0.0.1:8201"
		location = common.Location{0, 1}
		genAllocPath = "genallocs/gen_alloc_qi_cyprus2.json"
		etxZone = "zone-0-2"
	case "zone-0-2":
		wsUrl = "ws://127.0.0.1:8202"
		location = common.Location{0, 2}
		genAllocPath = "genallocs/gen_alloc_qi_cyprus3.json"
		etxZone = "zone-1-0"
	case "zone-1-0":
		wsUrl = "ws://127.0.0.1:8220"
		location = common.Location{1, 0}
		genAllocPath = "genallocs/gen_alloc_qi_paxos1.json"
		etxZone = "zone-1-1"
	case "zone-1-1":
		wsUrl = "ws://127.0.0.1:8221"
		location = common.Location{1, 1}
		genAllocPath = "genallocs/gen_alloc_qi_paxos2.json"
		etxZone = "zone-1-2"
	case "zone-1-2":
		wsUrl = "ws://127.0.0.1:8222"
		location = common.Location{1, 2}
		genAllocPath = "genallocs/gen_alloc_qi_paxos3.json"
		etxZone = "zone-2-0"
	case "zone-2-0":
		wsUrl = "ws://127.0.0.1:8240"
		location = common.Location{2, 0}
		genAllocPath = "genallocs/gen_alloc_qi_hydra1.json"
		etxZone = "zone-2-1"
	case "zone-2-1":
		wsUrl = "ws://127.0.0.1:8241"
		location = common.Location{2, 1}
		genAllocPath = "genallocs/gen_alloc_qi_hydra2.json"
		etxZone = "zone-2-2"
	case "zone-2-2":
		wsUrl = "ws://127.0.0.1:8242"
		location = common.Location{2, 2}
		genAllocPath = "genallocs/gen_alloc_qi_hydra3.json"
		etxZone = "zone-0-0"
	default:
		// Handle default case or invalid zone
		log.Fatalf("Invalid or no zone specified")
	}

	if viper.GetBool("enablePprof") {
		runtime.SetBlockProfileRate(1)
		runtime.SetMutexProfileFraction(1)
		go func() {
			fmt.Println(http.ListenAndServe("localhost:"+strconv.Itoa(utils.GetWSPort(location)+1010), nil))
		}()
	}

	selectedZone = *zoneFlag
	chainId = *chainIdFlag
	keysFile = *keysFileFlag
	group = *groupFlag

	// Initialize maps
	addressMap = make(map[common.AddressBytes]AddressData)
	etxAddresses = make([]common.AddressBytes, 0)
	spendableOutpoints = make(map[common.AddressBytes][]OutpointAndTxOut)
	backupSpendableOutpoints = make(map[common.AddressBytes][]OutpointAndTxOut)
	lowDenomOutpoints = make(map[common.AddressBytes][]OutpointAndTxOut)
	wsClient, err := ethclient.Dial(wsUrl)
	if err != nil {
		log.Fatalf("Failed to connect to the Ethereum WebSocket client: %v", err)
	}
	defer wsClient.Close()

	transactor := Transactor{
		client:    wsClient,
		config:    cfg,
		TargetTPS: cfg.BloomTps,
	}
	startTime = time.Now()
	// Load addresses and private keys from JSON file
	err = transactor.loadAddresses(keysFile, group)
	if err != nil {
		log.Fatalf("Error loading addresses: %v", err)
	}

	err = transactor.loadGenesisUtxosFromNode(true)
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
func (transactor *Transactor) loadAddresses(filename, groupName string) error {
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

	txMutex.Lock()
	defer txMutex.Unlock()

	zoneData := group[selectedZone]

	// block, err := transactor.client.BlockByNumber(context.Background(), nil)
	// if err != nil {
	// 	log.Printf("Failed to get latest block: %v", err)
	// 	return err
	// }

	for _, info := range zoneData {
		privateKey, err := crypto.HexToECDSA(info.PrivateKey[2:]) // Remove '0x' prefix
		if err != nil {
			log.Printf("Invalid private key for address %s: %v", info.Address, err)
			continue
		}
		if privateKey == nil {
			log.Printf("Invalid private key for address %s", info.Address)
			continue
		}
		btcecKey, _ := btcec.PrivKeyFromBytes(privateKey.D.Bytes())
		if btcecKey == nil {
			log.Printf("Failed to convert private key for address %s", info.Address)
			continue
		}
		secpKey := secp256k1.PrivKeyFromBytes(btcecKey.Serialize())
		if secpKey == nil {
			log.Printf("Failed to convert private key to secpKey for address %s", info.Address)
			continue
		}

		// address := common.HexToAddress(info.Address, location)
		// mixedCase := common.NewMixedcaseAddress(address)

		// balance, err := transactor.client.BalanceAt(context.Background(), mixedCase, block.Number(2))
		// if err != nil {
		// 	log.Printf("Failed to get balance for address %s: %v", info.Address, err)
		// 	continue
		// }

		// fmt.Printf("Loading Address: %s, balance %d\n", lowStrAddress, balance)

		s := AddressData{
			PrivateKey: secpKey,
			Balance:    big.NewInt(100000000),
			Location:   location,
		}
		addressMap[common.HexToAddressBytes(info.Address)] = s
		// Initialize spendableOutpoints map for this address
		spendableOutpoints[common.HexToAddressBytes(info.Address)] = make([]OutpointAndTxOut, 0)
	}

	for _, info := range group[etxZone] {
		etxAddresses = append(etxAddresses, common.HexToAddressBytes(info.Address))
	}

	return nil
}

func (transactor *Transactor) loadGenesisUtxosFromNode(loadBackups bool) error {
	start := time.Now()
	numOuts := 0
	for addr, _ := range addressMap {
		outpoints, err := transactor.client.GetOutpointsByAddress(context.Background(), common.NewMixedcaseAddress(common.Bytes20ToAddress(addr, location)))
		if err != nil {
			return fmt.Errorf("error getting outpoints by address: %v", err)
		}
		numOuts += len(outpoints)
		i := 0
		for _, outpoint := range outpoints {
			if outpoint.Denomination <= MIN_DENOMINATION {
				lowDenomOutpoints[addr] = append(lowDenomOutpoints[addr], OutpointAndTxOut{
					outpoint: types.NewOutPoint(&outpoint.TxHash, outpoint.Index),
					txOut:    types.NewTxOut(outpoint.Denomination, addr[:], big.NewInt(0)),
				})
			} else {
				if i%2 == 0 || !loadBackups {
					spendableOutpoints[addr] = append(spendableOutpoints[addr], OutpointAndTxOut{
						outpoint: types.NewOutPoint(&outpoint.TxHash, outpoint.Index),
						txOut:    types.NewTxOut(outpoint.Denomination, addr[:], big.NewInt(0)),
					})
				} else {
					backupSpendableOutpoints[addr] = append(backupSpendableOutpoints[addr], OutpointAndTxOut{
						outpoint: types.NewOutPoint(&outpoint.TxHash, outpoint.Index),
						txOut:    types.NewTxOut(outpoint.Denomination, addr[:], big.NewInt(0)),
					})
				}

			}
		}
	}
	fmt.Printf("Time to get %d outpoints: %s\n", numOuts, time.Since(start))
	return nil
}

// loadGenesisUtxos loads genesis UTXOs from a specified file
func (transactor *Transactor) loadGenesisUtxos(filename string) error {

	file, err := ioutil.ReadFile(filename)
	if err != nil {
		return fmt.Errorf("error reading file: %v", err)
	}
	var utxos map[string]GenesisUTXO
	if err := json.Unmarshal(file, &utxos); err != nil {
		return fmt.Errorf("error unmarshalling JSON: %v", err)
	}
	i := 0
	for address, utxo := range utxos {
		hash := common.HexToHash(utxo.Hash)
		outpoint := &types.OutPoint{TxHash: hash, Index: uint16(utxo.Index)}
		addr := common.Hex2Bytes(address)
		txOut := &types.TxOut{
			Address:      addr,
			Denomination: uint8(utxo.Denomination),
		}
		if addressMap[common.HexToAddressBytes(address)].PrivateKey == nil {
			continue
		}
		if txOut.Denomination <= MIN_DENOMINATION {
			return fmt.Errorf("Invalid denomination for genesis UTXO: %d", txOut.Denomination)
		}
		if i%4 == 0 {
			spendableOutpoints[common.HexToAddressBytes(address)] = append(spendableOutpoints[common.HexToAddressBytes(address)], OutpointAndTxOut{
				outpoint: outpoint,
				txOut:    txOut,
			})
			numStartingInputs++
		} else {
			backupSpendableOutpoints[common.HexToAddressBytes(address)] = append(backupSpendableOutpoints[common.HexToAddressBytes(address)], OutpointAndTxOut{
				outpoint: outpoint,
				txOut:    txOut,
			})
		}
		i++
	}
	return nil
}

// Create a transaction for a given input and output set
func (transactor *Transactor) makeUTXOTransaction(ins []types.TxIn, outs []types.TxOut, privKeys []*secp256k1.PrivateKey, pubKeys []*secp256k1.PublicKey) *types.Transaction {
	// key = hash(blockHash, index)
	// Find hash / index for originUtxo / imagine this is block hash

	chainId := big.NewInt(chainId)
	utxo := &types.QiTx{
		ChainID: chainId,
		TxIn:    ins,
		TxOut:   outs,
	}

	tx := types.NewTx(utxo)

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

	signedUtxo := &types.QiTx{
		ChainID:   chainId,
		TxIn:      tx.TxIn(),
		TxOut:     tx.TxOut(),
		Signature: sig,
	}

	signedTx := types.NewTx(signedUtxo)

	// Verify the transaction signature
	var finalKey *btcec.PublicKey
	if len(tx.TxIn()) > 1 {
		aggKey, _, _, err := musig2.AggregateKeys(
			pubKeys, false,
		)
		if err != nil {
			return nil
		}
		finalKey = aggKey.FinalKey
	} else {
		finalKey = pubKeys[0]
	}

	if !sig.Verify(txHash[:], finalKey) {
		log.Fatal("Failed to verify signature")
	}

	txDigestHash := signer.Hash(tx)
	if !signedTx.GetSchnorrSignature().Verify(txDigestHash[:], finalKey) {
		log.Fatalf("Failed to verify signature, len pubkeys %d", len(pubKeys))
		return nil
	}

	// Send the transaction
	err = transactor.client.SendTransaction(context.Background(), signedTx)
	if err != nil {
		log.Printf("Failed to send transaction: %v", err)
	}

	return tx
}

// listenForNewBlocks listens for new blocks and processes them
func (transactor *Transactor) listenForNewBlocks() {
	// Subscribe to new block headers
	headers := make(chan *types.WorkObject, 10000)
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
			if (header == &types.WorkObject{}) {
				continue
			}
			headerHashes = append(headerHashes, header.Hash())
			time.Sleep(10 * time.Millisecond) // Sleep to rate limit block processing
			transactor.getBlockAndTransactions(header.Hash())
		}
	}
}

var totalTransactions int

// getBlockAndTransactions listens for the block and transactions
// after the block is received, it will process the transactions
// and update the spendableOutpoints map
func (transactor *Transactor) getBlockAndTransactions(hash common.Hash) {
	// Retrieve the block by its hash
	block, err := transactor.client.BlockByHash(context.Background(), hash)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			time.Sleep(100 * time.Millisecond) // wait for block to be stored
			block, err = transactor.client.BlockByHash(context.Background(), hash)
			if err != nil {
				fmt.Printf("Failed to retrieve the block after trying twice: %s %s\n", hash, err)
				return
			}
		} else {
			fmt.Printf("Failed to retrieve the block: %s %s\n", hash, err)
			return
		}

	}

	// Display block information
	fmt.Printf("number: %d txs: %d  hash: %s\n", block.WorkObjectHeader().NumberU64(), len(block.QiTransactions()), block.Hash().Hex())

	// Calculate TPS based on block time
	currentBlockInfo := blockInfo{
		Time:             time.Unix(int64(block.Time()), 0),
		TransactionCount: len(block.QiTransactions()),
	}
	blockInfos = append(blockInfos, currentBlockInfo)
	if len(blockInfos) > maxBlocks {
		blockInfos = blockInfos[1:] // Keep only the last 50 blocks
	}
	totalTransactions += currentBlockInfo.TransactionCount
	// Calculate weighted TPS
	if len(blockInfos) >= maxBlocks {
		var transactions int
		var totalTime float64
		for i := 1; i < len(blockInfos); i++ {
			transactions += blockInfos[i].TransactionCount
			totalTime += blockInfos[i].Time.Sub(blockInfos[i-1].Time).Seconds()
		}
		if totalTime > 0 {
			weightedTPS := float64(transactions) / totalTime
			fmt.Printf("Total Transactions: %d Weighted TPS (last %d blocks): %f\n", totalTransactions, len(blockInfos), weightedTPS)
			transactor.CurrentTPS = weightedTPS
		}
	}

	// Iterate over and display transactions in the block
	txMutex.Lock()
	defer txMutex.Unlock()
	for _, tx := range block.QiTransactions() {
		for i, txOut := range tx.TxOut() {
			outpoint := &types.OutPoint{TxHash: tx.Hash(), Index: uint16(i)}
			addressStr := "0x" + common.Bytes2Hex(txOut.Address)
			addr := common.HexToAddressBytes(addressStr)
			// Check if the address is one of the loaded addresses with a private key
			if _, exists := addressMap[addr]; exists {
				txOutCopy := txOut
				outpointAndTxOut := OutpointAndTxOut{outpoint, &txOutCopy}
				if txOut.Denomination <= MIN_DENOMINATION {
					lowDenoms := lowDenomOutpoints[addr]
					if lowDenoms == nil {
						lowDenomOutpoints[addr] = make([]OutpointAndTxOut, 0)
					}
					lowDenomOutpoints[addr] = append(lowDenomOutpoints[addr], outpointAndTxOut)
					addressMap[addr].Balance.Add(addressMap[addr].Balance, types.Denominations[txOut.Denomination])
				} else {
					// Append the outpoint to the spendableOutpoints map for the address
					spendableOutpoints[addr] = append(spendableOutpoints[addr], outpointAndTxOut)

					// Track the balance of added outpoints
					addressMap[addr].Balance.Add(addressMap[addr].Balance, types.Denominations[txOut.Denomination])
					// fmt.Printf("Receiving Address: %s, balance %d\n", addressStr, addressMap[addressStr].Balance)
				}
			}
		}
	}
	for _, tx := range block.Body().ExternalTransactions() {
		if tx.To().IsInQiLedgerScope() {
			if tx.ETXSender().Location().Equal(*tx.To().Location()) {
				// Quai->Qi conversion, utxo is locked
				continue
			}
			outpoint := &types.OutPoint{TxHash: tx.OriginatingTxHash(), Index: tx.ETXIndex()}
			if _, exists := addressMap[tx.To().Bytes20()]; exists {
				outpointAndTxOut := OutpointAndTxOut{outpoint, types.NewTxOut(uint8(tx.Value().Uint64()), tx.To().Bytes(), big.NewInt(0))}
				if outpointAndTxOut.txOut.Denomination <= MIN_DENOMINATION {
					lowDenoms := lowDenomOutpoints[tx.To().Bytes20()]
					if lowDenoms == nil {
						lowDenomOutpoints[tx.To().Bytes20()] = make([]OutpointAndTxOut, 0)
					}
					lowDenomOutpoints[tx.To().Bytes20()] = append(lowDenomOutpoints[tx.To().Bytes20()], outpointAndTxOut)
					addressMap[tx.To().Bytes20()].Balance.Add(addressMap[tx.To().Bytes20()].Balance, types.Denominations[outpointAndTxOut.txOut.Denomination])
				} else {
					spendableOutpoints[tx.To().Bytes20()] = append(spendableOutpoints[tx.To().Bytes20()], outpointAndTxOut)
					addressMap[tx.To().Bytes20()].Balance.Add(addressMap[tx.To().Bytes20()].Balance, types.Denominations[uint8(tx.Value().Uint64())])
				}
			}
		}
	}

	totalOuts := 0
	totalLowDenomOutpoints := 0
	for _, outpoints := range spendableOutpoints {
		totalOuts += len(outpoints)
	}
	totalNumOuts = totalOuts
	for _, outpoints := range lowDenomOutpoints {
		totalLowDenomOutpoints += len(outpoints)
	}
	totalLowDenomOuts = totalLowDenomOutpoints
	// Check if we are running out of outputs
	if totalOuts <= 100 && !createMaxOutputs && time.Since(startTime) > time.Minute*10 {
		fmt.Printf("Running out of outputs - using backup!\n")
		// Use backup spendable outpoints
		i := 0
		outpointsAdded := 0
		for address, outpoints := range backupSpendableOutpoints {
			if i%2 == 0 {
				spendableOutpoints[address] = append(spendableOutpoints[address], outpoints...)
				delete(backupSpendableOutpoints, address)
				i++
				outpointsAdded += len(outpoints)
			}
		}
		if outpointsAdded < 100 {
			// Resync from node
			err := transactor.loadGenesisUtxosFromNode(false)
			if err != nil {
				fmt.Printf("Error loading genesis UTXOs: %v\n", err)
			}
		}
		createMaxOutputs = true
		startTime = time.Now() // Begin bloom process again
		numTxsSent = 0
		totalTxCreationTime = time.Duration(0)
		transactor.TargetTPS = transactor.config.BloomTps
	} else if createMaxOutputs && (totalOuts > 250000 || time.Since(startTime) > time.Hour*2) {
		createMaxOutputs = false
		transactor.TargetTPS = transactor.config.TargetTps
	}
	fmt.Printf("Total outpoints: %d LowDenomOutpoints: %d Blooming: %t\n", totalOuts, totalLowDenomOutpoints, createMaxOutputs)
}

// createTransactions creates a new transaction for each address with a private key
// on a continuous loop. Will pick up low denomination outpoints and schedule
// for consolidation.
func (transactor *Transactor) createTransactions() {
	rand.Seed(time.Now().UnixNano()) // Seed the random number generator
	numEtxs := 0
	noSpendableOutputs := 0
	txTime := time.Now()
	// assume it takes 3 ms to construct a transaction
	txCreationTime := time.Duration(3) * time.Millisecond
	tpsPerMachine := transactor.TargetTPS / transactor.config.MachinesRunning
	targetSleepTime := (time.Second / time.Duration(tpsPerMachine)) - txCreationTime
	if targetSleepTime < 0 {
		targetSleepTime = 0
	}
	totalOuts := 0
	for _, outpoints := range spendableOutpoints {
		totalOuts += len(outpoints)
	}
	totalNumOuts = totalOuts
	createMaxOutputs = true
	for {

		prevNumTxs := numTxsSent
		txMutex.Lock() // lock to read the spendableOutpoints map
		for address, outpoints := range spendableOutpoints {
			txCreationStart := time.Now()
			txMutex.Unlock()
			txMutex.Lock()
			if len(outpoints) == 0 {
				// Don't unlock here because it's unlocked in the next iteration
				continue // Skip if no outpoints or no private key
			}
			if addressMap[address].PrivateKey == nil {
				fmt.Printf("No private key for address: %s\n", address)
				continue
			}
			i := 0
			selectedOutpoint := outpoints[i] // Select first output
			if selectedOutpoint.txOut.Denomination <= MIN_DENOMINATION {
				// This address does not have any spendable outpoints
				fmt.Printf("Outpoint is low denomination: %d\n", selectedOutpoint.txOut.Denomination)
				continue
			}
			maxOutputs := new(big.Int).Div(types.Denominations[selectedOutpoint.txOut.Denomination], types.Denominations[selectedOutpoint.txOut.Denomination-1]).Uint64()
			numOuts := 3
			if selectedOutpoint.txOut.Denomination < 10 || uint64(numOuts) >= maxOutputs {
				numOuts = int(maxOutputs - 1)
			}
			if numTxsSent%int(1/transactor.config.MaxOutputsFreq) == 0 && selectedOutpoint.txOut.Denomination > 0 {
				numOuts = int(maxOutputs) - 1
			}
			if createMaxOutputs {
				numOuts = int(maxOutputs) - 1
			}
			denomIndex := selectedOutpoint.txOut.Denomination - 1
			if selectedOutpoint.txOut.Denomination == 0 {
				denomIndex = 0
			}

			addresses := make(map[common.AddressBytes]bool)

			in := types.TxIn{
				PreviousOutPoint: *types.NewOutPoint(&selectedOutpoint.outpoint.TxHash, selectedOutpoint.outpoint.Index),
				PubKey:           addressMap[address].PrivateKey.PubKey().SerializeUncompressed(),
			}

			privKeys := []*secp256k1.PrivateKey{addressMap[address].PrivateKey}
			pubKeys := []*secp256k1.PublicKey{addressMap[address].PrivateKey.PubKey()}
			inputs := []types.TxIn{in}
			foundFeeInput := false
			// Add a single low denomination outpoint to the transaction for fee
			for address, outpoints := range lowDenomOutpoints {
				if len(outpoints) == 0 || addressMap[address].PrivateKey == nil || addresses[address] == true {
					continue // Skip if no outpoints or no private key
				}
				lowDenomOutPoint := outpoints[0]
				inputs = append(inputs, types.TxIn{
					PreviousOutPoint: *types.NewOutPoint(&lowDenomOutPoint.outpoint.TxHash, lowDenomOutPoint.outpoint.Index),
					PubKey:           addressMap[address].PrivateKey.PubKey().SerializeUncompressed(),
				})
				privKeys = append(privKeys, addressMap[address].PrivateKey)
				pubKeys = append(pubKeys, addressMap[address].PrivateKey.PubKey())
				addresses[address] = true
				lowDenomOutpoints[address] = lowDenomOutpoints[address][1:] // Remove the first outpoint used
				if IntrinsicFee(uint64(len(inputs)), uint64(numOuts)).Cmp(types.Denominations[lowDenomOutPoint.txOut.Denomination]) <= 1 {
					foundFeeInput = true
					if createMaxOutputs {
						denomIndex = selectedOutpoint.txOut.Denomination - 1
						numOuts = int(maxOutputs)
					} else {
						denomIndex = selectedOutpoint.txOut.Denomination
						numOuts = 1
					}
					break
				}
			}
			addresses[address] = true

			outs := make([]types.TxOut, 0)
			for i := 0; i < numOuts; i++ {
				etx := false
				if transactor.config.EtxFreq > 0 && numTxsSent%(int(1/transactor.config.EtxFreq)) == 0 && i == 0 {
					etx = true
				}
				toAddress := getRandomAddress(addressMap, etx)
				if !toAddress.Location().Equal(location) {
					numEtxs++
				}
				if _, exists := addresses[toAddress]; exists {
					i-- // Try again if the address is already used
					continue
				}

				newOut := types.TxOut{
					Denomination: uint8(denomIndex),
					Address:      toAddress[:],
				}
				outs = append(outs, newOut)

				// Track the balance of added outpoints
				if !etx {
					addressMap[toAddress].Balance.Add(addressMap[toAddress].Balance, types.Denominations[uint8(denomIndex)])
				}
				addresses[toAddress] = true
			}
			if numOuts == int(maxOutputs-1) && !foundFeeInput {
				// Add a low denomination output
				toAddress := getRandomAddress(addressMap, false)
				if _, exists := addresses[toAddress]; exists {
					toAddress = getRandomAddress(addressMap, false) // Try again if the address is already used
				}
				newOut := types.TxOut{
					Denomination: MIN_DENOMINATION,
					Address:      toAddress[:],
				}
				outs = append(outs, newOut)
				addressMap[toAddress].Balance.Add(addressMap[toAddress].Balance, types.Denominations[MIN_DENOMINATION])
				addresses[toAddress] = true
			}
			//fmt.Println("Creating transaction for address: ", address, " with ", len(outs), " outputs")
			spendableOutpoints[address] = spendableOutpoints[address][1:] // Remove the first outpoint used
			totalNumOuts--
			txMutex.Unlock()
			transactor.makeUTXOTransaction(inputs, outs, privKeys, pubKeys)
			totalTxCreationTime += time.Since(txCreationStart)
			time.Sleep(targetSleepTime)
			numTxsSent++
			// Adjust the sleep time every 5 seconds
			// Adjust sleep time using PI controller
			if time.Since(txTime) > time.Second*5 && time.Since(startTime) > time.Minute {
				totalAverageTpsFromMyPerspective := (float64(numTxsSent) / float64(time.Since(startTime).Seconds()))
				calculatedErrorFromMyPerspective := float64(transactor.TargetTPS)/float64(transactor.config.MachinesRunning) - totalAverageTpsFromMyPerspective
				calculatedErrorFromTheNodePerspective := float64(transactor.TargetTPS) - transactor.CurrentTPS
				Error := (calculatedErrorFromTheNodePerspective + calculatedErrorFromTheNodePerspective + calculatedErrorFromMyPerspective) / 3
				if transactor.CurrentTPS == 0 || createMaxOutputs { // Do not use block tps during bloom
					Error = calculatedErrorFromMyPerspective
				}
				txTime = time.Now()
				fmt.Printf("Target: %d Error: %f BlockTps: %f TotalAverageCalcTps: %f NumOuts: %d SentEtxs: %d Average tx creation time: %s\n", transactor.TargetTPS, Error, transactor.CurrentTPS, totalAverageTpsFromMyPerspective, totalNumOuts, numEtxs, common.PrettyDuration(totalTxCreationTime/time.Duration(numTxsSent)))
				fmt.Printf("Previous sleep time: %s\n", targetSleepTime)
				delta := time.Duration(transactor.config.Kp * Error * 1e9) // 1e9 converts seconds to nanoseconds and 1e6 converts milliseconds to nanoseconds
				targetSleepTime = targetSleepTime - delta
				fmt.Printf("Delta: %s\n", delta)
				fmt.Printf("New sleep time: %s\n", targetSleepTime)
				// Avoid negative or excessively long sleep times
				if targetSleepTime < 0 {
					targetSleepTime = 0
				} else if targetSleepTime > time.Second {
					targetSleepTime = time.Second
				}
			}
			txMutex.Lock() // Lock for reading the next iteration
		}
		txMutex.Unlock()
		if prevNumTxs == numTxsSent {
			noSpendableOutputs++
			if noSpendableOutputs%1000 == 0 {
				fmt.Println("No spendable outpoints available.")
				time.Sleep(time.Minute)
				fmt.Printf("Running out of outputs - using backup!")
				// Use backup spendable outpoints
				i := 0
				txMutex.Lock()
				outpointsAdded := 0
				for address, outpoints := range backupSpendableOutpoints {
					if i%2 == 0 {
						spendableOutpoints[address] = append(spendableOutpoints[address], outpoints...)
						delete(backupSpendableOutpoints, address)
						i++
						outpointsAdded += len(outpoints)
					}
				}
				if outpointsAdded < 100 {
					// Resync from node
					err := transactor.loadGenesisUtxosFromNode(false)
					if err != nil {
						fmt.Printf("Error loading genesis UTXOs: %v\n", err)
					}
				}
				startTime = time.Now() // Begin bloom process again
				numTxsSent = 0
				totalTxCreationTime = time.Duration(0)
				createMaxOutputs = true
				transactor.TargetTPS = transactor.config.BloomTps
				totalOuts := 0
				for _, outpoints := range spendableOutpoints {
					totalOuts += len(outpoints)
				}
				totalNumOuts = totalOuts
				txMutex.Unlock()
			}
		}
	}

}

// Utility function to get a random address from addressMap, excluding the input address
func getRandomAddress(addressMap map[common.AddressBytes]AddressData, etx bool) common.AddressBytes {
	keys := make([]common.AddressBytes, 0, len(addressMap))
	for k := range addressMap {
		keys = append(keys, k)
	}
	if len(keys) == 0 {
		return common.AddressBytes{} // Handle case where addressMap is empty
	}
	randIndex := rand.Intn(len(keys))
	if etx {
		randIndex = rand.Intn(len(etxAddresses))
		return etxAddresses[randIndex]
	}
	if addressMap[keys[randIndex]].PrivateKey == nil {
		return getRandomAddress(addressMap, etx) // Try again if the address has no private key
	}
	return keys[randIndex]
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

func Contains(outpoints *[]OutpointAndTxOut, outpoint OutpointAndTxOut) bool {
	for _, o := range *outpoints {
		if o.outpoint.TxHash == outpoint.outpoint.TxHash && o.outpoint.Index == outpoint.outpoint.Index {
			return true
		}
	}
	return false
}

func IntrinsicFee(txIns, txOuts uint64) *big.Int {
	return new(big.Int).Mul(big.NewInt(params.GWei), new(big.Int).SetUint64(uint64(txIns*params.SloadGas+txOuts*params.CallValueTransferGas+params.EcrecoverGas)))
}
