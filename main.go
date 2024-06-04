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
	"sync"
	"syscall"
	"time"

	"flag"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcec/v2/schnorr/musig2"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
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
	addressMap         map[common.AddressBytes]AddressData        // Map address to balance and location
	etxAddresses       []common.AddressBytes                      // Map address to balance and location
	spendableOutpoints map[common.AddressBytes][]OutpointAndTxOut // Map address to spendable outpoints
	lowDenomOutpoints  map[common.AddressBytes][]OutpointAndTxOut
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
}

type Config struct {
	Env             string  `json:"env"`
	BlockTime       int     `json:"blockTime"`
	MachinesRunning int     `json:"machinesRunning"`
	TargetTps       int     `json:"targetTps"`
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

	selectedZone = *zoneFlag
	chainId = *chainIdFlag
	keysFile = *keysFileFlag
	group = *groupFlag

	// Initialize maps
	addressMap = make(map[common.AddressBytes]AddressData)
	etxAddresses = make([]common.AddressBytes, 0)
	spendableOutpoints = make(map[common.AddressBytes][]OutpointAndTxOut)
	lowDenomOutpoints = make(map[common.AddressBytes][]OutpointAndTxOut)
	wsClient, err := ethclient.Dial(wsUrl)
	if err != nil {
		log.Fatalf("Failed to connect to the Ethereum WebSocket client: %v", err)
	}
	defer wsClient.Close()

	transactor := Transactor{
		client: wsClient,
		config: cfg,
	}

	// Load addresses and private keys from JSON file
	err = transactor.loadAddresses(keysFile, group)
	if err != nil {
		log.Fatalf("Error loading addresses: %v", err)
	}

	err = transactor.loadGenesisUtxos(genAllocPath)
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

	for address, utxo := range utxos {
		hash := common.HexToHash(utxo.Hash)
		outpoint := &types.OutPoint{TxHash: hash, Index: uint16(utxo.Index)}
		addr := common.Hex2Bytes(address)
		txOut := &types.TxOut{
			Address:      addr,
			Denomination: uint8(utxo.Denomination),
		}
		spendableOutpoints[common.HexToAddressBytes(address)] = append(spendableOutpoints[common.HexToAddressBytes(address)], OutpointAndTxOut{
			outpoint: outpoint,
			txOut:    txOut,
		})
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
		fmt.Printf("Failed to retrieve the block: %s %s\n", hash, err)
		return
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
				outpointAndTxOut := OutpointAndTxOut{outpoint, &txOut}
				// Append the outpoint to the spendableOutpoints map for the address
				spendableOutpoints[addr] = append(spendableOutpoints[addr], outpointAndTxOut)

				// Track the balance of added outpoints
				addressMap[addr].Balance.Add(addressMap[addr].Balance, types.Denominations[txOut.Denomination])
				// fmt.Printf("Receiving Address: %s, balance %d\n", addressStr, addressMap[addressStr].Balance)
			}
		}
	}
	/*for _, tx := range block.Body().ExternalTransactions() {

	}*/

	totalOuts := 0
	totalLowDenomOutpoints := 0
	for _, outpoints := range spendableOutpoints {
		totalOuts += len(outpoints)
	}
	for _, outpoints := range lowDenomOutpoints {
		totalLowDenomOutpoints += len(outpoints)
	}
	fmt.Printf("Total outpoints: %d LowDenomOutpoints: %d\n", totalOuts, totalLowDenomOutpoints)
}

// createTransactions creates a new transaction for each address with a private key
// on a continuous loop. Will pick up low denomination outpoints and schedule
// for consolidation.
func (transactor *Transactor) createTransactions() {
	rand.Seed(time.Now().UnixNano()) // Seed the random number generator
	numTxs := 0
	numEtxs := 0
	startTime := time.Now()
	txTime := time.Now()
	integral := 0.0
	// assume it takes 3 ms to construct a transaction
	txCreationTime := time.Duration(3) * time.Millisecond
	totalTxCreationTime := time.Duration(0)
	tpsPerMachine := transactor.config.TargetTps / transactor.config.MachinesRunning
	targetSleepTime := (time.Second / time.Duration(tpsPerMachine)) - txCreationTime
	if targetSleepTime < 0 {
		targetSleepTime = 0
	}
	toAddresses := make(map[string]uint)
	for {

		prevNumTxs := numTxs
		txMutex.Lock() // lock to read the spendableOutpoints map
		for address, outpoints := range spendableOutpoints {
			txMutex.Unlock()
			txCreationStart := time.Now()
			txMutex.Lock()
			if len(outpoints) == 0 || addressMap[address].PrivateKey == nil {
				// Don't unlock here because it's unlocked in the next iteration
				continue // Skip if no outpoints or no private key
			}
			i := 0
			selectedOutpoint := outpoints[i]                              // Select first output
			for selectedOutpoint.txOut.Denomination <= MIN_DENOMINATION { // Skip low denomination outpoints
				lowDenoms := lowDenomOutpoints[address]
				if lowDenoms == nil {
					lowDenomOutpoints[address] = make([]OutpointAndTxOut, 0)
				} else if Contains(&lowDenoms, selectedOutpoint) {
					// Skip if the outpoint is already in the lowDenomOutpoints list
					if i >= len(outpoints)-1 {
						break
					}
					i++
					selectedOutpoint = outpoints[i]
					continue
				}
				lowDenomOutpoints[address] = append(lowDenomOutpoints[address], selectedOutpoint)
				if i >= len(outpoints)-1 {
					break
				}
				i++
				selectedOutpoint = outpoints[i]
			}
			if selectedOutpoint.txOut.Denomination <= MIN_DENOMINATION {
				// This address does not have any spendable outpoints
				continue
			}
			maxOutputs := new(big.Int).Div(types.Denominations[selectedOutpoint.txOut.Denomination], types.Denominations[selectedOutpoint.txOut.Denomination-1]).Uint64()
			numOuts := 3
			if selectedOutpoint.txOut.Denomination < 10 || uint64(numOuts) >= maxOutputs {
				numOuts = int(maxOutputs - 1)
			}
			if numTxs%int(1/transactor.config.MaxOutputsFreq) == 0 && selectedOutpoint.txOut.Denomination > 0 {
				numOuts = int(maxOutputs) - 1
			}

			denomIndex := selectedOutpoint.txOut.Denomination - 1
			if selectedOutpoint.txOut.Denomination == 0 {
				denomIndex = 0
			}

			addresses := make(map[common.AddressBytes]struct{})

			in := types.TxIn{
				PreviousOutPoint: *types.NewOutPoint(&selectedOutpoint.outpoint.TxHash, selectedOutpoint.outpoint.Index),
				PubKey:           addressMap[address].PrivateKey.PubKey().SerializeUncompressed(),
			}

			privKeys := []*secp256k1.PrivateKey{addressMap[address].PrivateKey}
			pubKeys := []*secp256k1.PublicKey{addressMap[address].PrivateKey.PubKey()}
			inputs := []types.TxIn{in}
			//foundFeeInput := true
			// Add a single low denomination outpoint to the transaction for fee
			for address, outpoints := range lowDenomOutpoints {
				if len(outpoints) == 0 || addressMap[address].PrivateKey == nil {
					continue // Skip if no outpoints or no private key
				}
				lowDenomOutPoint := outpoints[0]
				inputs = append(inputs, types.TxIn{
					PreviousOutPoint: *types.NewOutPoint(&lowDenomOutPoint.outpoint.TxHash, lowDenomOutPoint.outpoint.Index),
					PubKey:           addressMap[address].PrivateKey.PubKey().SerializeUncompressed(),
				})
				privKeys = append(privKeys, addressMap[address].PrivateKey)
				pubKeys = append(pubKeys, addressMap[address].PrivateKey.PubKey())
				addresses[address] = struct{}{}
				lowDenomOutpoints[address] = lowDenomOutpoints[address][1:] // Remove the first outpoint used
				if IntrinsicFee(uint64(len(inputs)), uint64(numOuts)).Cmp(types.Denominations[lowDenomOutPoint.txOut.Denomination]) == 1 {
					//foundFeeInput = true
					denomIndex = selectedOutpoint.txOut.Denomination
					numOuts = 1
					break
				}
			}
			addresses[address] = struct{}{}

			outs := make([]types.TxOut, 0)
			for i := 0; i < numOuts; i++ {
				etx := false
				if transactor.config.EtxFreq > 0 && numTxs%(int(1/transactor.config.EtxFreq)) == 0 && i == 0 {
					etx = true
				}
				toAddress := getRandomAddress(addressMap, etx)
				if !toAddress.Location().Equal(location) {
					numEtxs++
				}
				toAddresses[toAddress.Location().Name()]++
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
				addresses[toAddress] = struct{}{}
			}
			//fmt.Println("Creating transaction for address: ", address, " with ", len(outs), " outputs")
			spendableOutpoints[address] = spendableOutpoints[address][1:] // Remove the first outpoint used
			txMutex.Unlock()
			transactor.makeUTXOTransaction(inputs, outs, privKeys, pubKeys)
			totalTxCreationTime += time.Since(txCreationStart)
			time.Sleep(targetSleepTime)
			numTxs++
			// Adjust the sleep time every 5 seconds
			// Adjust sleep time using PI controller
			if time.Since(txTime) > time.Second*5 && time.Since(startTime) > time.Minute {
				totalAverageTps := (float64(numTxs) / float64(time.Since(startTime).Seconds()))
				calculatedError := float64(transactor.config.TargetTps)/float64(transactor.config.MachinesRunning) - totalAverageTps
				Error := ((float64(transactor.config.TargetTps) - transactor.CurrentTPS) + calculatedError) / 2
				integral += (Error / 1000) * float64(time.Since(txTime).Milliseconds())
				txTime = time.Now()
				fmt.Printf("Error: %f BlockTps: %f TotalAverageCalcTps: %f Etxs: %d Integral: %f\n", Error, transactor.CurrentTPS, totalAverageTps, numEtxs, transactor.config.Ki*integral)
				fmt.Printf("Previous sleep time: %s\n", targetSleepTime)
				targetSleepTime = targetSleepTime - time.Duration(transactor.config.Kp*Error*1e9) + time.Duration(transactor.config.Ki*integral*1e6) // 1e9 converts seconds to nanoseconds and 1e6 converts milliseconds to nanoseconds
				fmt.Printf("New sleep time: %s\n", targetSleepTime)
				for k, v := range toAddresses {
					fmt.Printf("Location: %s, Count: %d\n", k, v)
				}
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
		if prevNumTxs == numTxs {
			fmt.Println("No spendable outpoints available.")
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
