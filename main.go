package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"log"
	"math/big"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/dominant-strategies/go-quai/common"
	"github.com/dominant-strategies/go-quai/core/types"
	"github.com/dominant-strategies/go-quai/crypto"
	"github.com/dominant-strategies/go-quai/quaiclient/ethclient"
)

const httpUrl = "http://localhost:9003"
const wsUrl = "ws://localhost:8003"
const privKey = "345debf66bc68724062b236d3b0a6eb30f051e725ebb770f1dc367f2c569f003"

var location = common.Location{0, 0}

var (
	headerHashes []common.Hash
	hashMutex    sync.Mutex
)

func main() {

	go listenForNewBlocks()
	go createTransactions()

	// Wait for an interrupt signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	fmt.Println("Shutting down...")
	// Perform any cleanup if necessary
}

func makeUTXOTransaction(outpointHash common.Hash, outpointIndex uint32, from common.Address, to common.Address, btcecKey *secp256k1.PrivateKey, pubKey []byte) *types.Transaction {
	// key = hash(blockHash, index)
	// Find hash / index for originUtxo / imagine this is block hash
	prevOut := *types.NewOutPoint(&outpointHash, outpointIndex)

	in := types.TxIn{
		PreviousOutPoint: prevOut,
		PubKey:           pubKey,
	}

	newOut := types.TxOut{
		Denomination: uint8(1),
		Address:      to.Bytes(),
	}

	utxo := &types.UtxoTx{
		TxIn:  []types.TxIn{in},
		TxOut: []types.TxOut{newOut},
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

	fmt.Println("Signed Raw Transaction")
	fmt.Println("Signature:", common.Bytes2Hex(sig.Serialize()))
	fmt.Println("TX Hash", common.Bytes2Hex(txHash[:]))
	fmt.Println("Pubkey", common.Bytes2Hex(pubKey))

	// Connect to the Ethereum client
	client, err := ethclient.Dial(httpUrl)
	if err != nil {
		log.Fatalf("Failed to connect to the Ethereum client: %v", err)
	}

	// Send the transaction
	err = client.SendTransaction(context.Background(), signedTx)
	if err != nil {
		log.Fatalf("Failed to send transaction: %v", err)
	}

	fmt.Println()

	return tx
}

func listenForNewBlocks() {
	// Connect to the Ethereum client via WebSocket
	wsClient, err := ethclient.Dial(wsUrl)
	if err != nil {
		log.Fatalf("Failed to connect to the Ethereum WebSocket client: %v", err)
	}
	defer wsClient.Close()

	// Subscribe to new block headers
	headers := make(chan *types.Header)
	sub, err := wsClient.SubscribeNewHead(context.Background(), headers)
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
			fmt.Println("New block:", header.NumberArray(), "Hash:", header.Hash().Hex())
			hashMutex.Lock()
			headerHashes = append(headerHashes, header.Hash())
			hashMutex.Unlock()
		}
	}
}

func createTransactions() {
	// Load your private key
	privateKey, err := crypto.HexToECDSA(privKey)
	if err != nil {
		log.Fatalf("Invalid private key: %v", err)
	}

	b, err := hex.DecodeString(privKey)
	if err != nil {
		fmt.Println(err)
	}

	// btcec key for schnorr use
	btcecKey, _ := btcec.PrivKeyFromBytes(b)
	uncompressedPubkey := btcecKey.PubKey().SerializeUncompressed()
	fromAddress := crypto.PubkeyToAddress(privateKey.PublicKey, location)
	toAddress := common.HexToAddress("0x1aCC3AF2647375A76bFB813B9b22Ec08e179110A", location)

	for {
		hashMutex.Lock()
		if len(headerHashes) > 0 {
			// Use the first hash and remove it from the slice
			hash := headerHashes[0]
			headerHashes = headerHashes[1:]
			hashMutex.Unlock()

			// Now use this hash to create a transaction
			makeUTXOTransaction(hash, 0, fromAddress, toAddress, btcecKey, uncompressedPubkey)
		} else {
			hashMutex.Unlock()
			// Sleep for a while before checking again
			// time.Sleep(1 * time.Second)
		}
	}
}
