package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"log"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/dominant-strategies/go-quai/common"
	"github.com/dominant-strategies/go-quai/core/types"
	"github.com/dominant-strategies/go-quai/crypto"
	"github.com/dominant-strategies/go-quai/quaiclient/ethclient"
)

const url = "http://localhost:8610"
const privKey = "345debf66bc68724062b236d3b0a6eb30f051e725ebb770f1dc367f2c569f003"

func main() {
	// Connect to the Ethereum client
	client, err := ethclient.Dial(url)
	if err != nil {
		log.Fatalf("Failed to connect to the Ethereum client: %v", err)
	}

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
	fromAddress := crypto.PubkeyToAddress(privateKey.PublicKey)
	toAddress := common.HexToAddress("0x1aCC3AF2647375A76bFB813B9b22Ec08e179110A")

	// Create the transaction
	tx := makeUTXOTransaction(fromAddress, toAddress, uncompressedPubkey)
	txHash := tx.Hash().Bytes()

	sig, err := schnorr.Sign(btcecKey, txHash[:])
	if err != nil {
		log.Fatalf("Failed to sign transaction: %v", err)
	}

	utxo := &types.UtxoTx{
		TxIn:      tx.TxIn(),
		TxOut:     tx.TxOut(),
		Signature: sig.Serialize(),
	}

	signedTx := types.NewTx(utxo)

	if !sig.Verify(txHash[:], btcecKey.PubKey()) {
		log.Fatal("Failed to verify signature")
	}

	rawUtxo := &types.UtxoTx{
		TxIn:  tx.TxIn(),
		TxOut: tx.TxOut(),
	}

	rawTx := types.NewTx(rawUtxo)

	txHash = rawTx.Hash().Bytes()

	fmt.Println("Signed Raw Transaction")
	fmt.Println("Signature:", common.Bytes2Hex(sig.Serialize()))
	fmt.Println("TX Hash", common.Bytes2Hex(txHash[:]))
	fmt.Println("Pubkey", common.Bytes2Hex(uncompressedPubkey))

	// Send the transaction
	err = client.SendTransaction(context.Background(), signedTx)
	if err != nil {
		log.Fatalf("Failed to send transaction: %v", err)
	}
}

func makeUTXOTransaction(from common.Address, to common.Address, pubKey []byte) *types.Transaction {
	outpointHash := common.HexToHash("471101dc4a407999500a718c4f9659abc8b01bbca5220a19a7549b53ca11ff6a")
	outpointIndex := uint32(0)

	// key = hash(blockHash, index)
	// Find hash / index for originUtxo / imagine this is block hash
	prevOut := *types.NewOutPoint(&outpointHash, outpointIndex)

	in := types.TxIn{
		PreviousOutPoint: prevOut,
		PubKey:           pubKey,
	}

	newOut := types.TxOut{
		Value: 10000000,
		// Value:    blockchain.CalcBlockSubsidy(nextBlockHeight, params),
		Address: to.Bytes(),
	}

	utxo := &types.UtxoTx{
		TxIn:  []types.TxIn{in},
		TxOut: []types.TxOut{newOut},
	}

	tx := types.NewTx(utxo)

	return tx
}
