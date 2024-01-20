package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"log"
	"math/big"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/dominant-strategies/go-quai/common"
	"github.com/dominant-strategies/go-quai/core/types"
	"github.com/dominant-strategies/go-quai/crypto"
	"github.com/dominant-strategies/go-quai/quaiclient/ethclient"
)

const url = "http://localhost:9003"
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

	location := common.Location{0, 0}

	// btcec key for schnorr use
	btcecKey, _ := btcec.PrivKeyFromBytes(b)
	uncompressedPubkey := btcecKey.PubKey().SerializeUncompressed()
	fromAddress := crypto.PubkeyToAddress(privateKey.PublicKey, location)
	fmt.Println("From Address: ", fromAddress.Hex())

	toAddress := common.HexToAddress("0x1aCC3AF2647375A76bFB813B9b22Ec08e179110A", location)

	// Create the transaction
	tx := makeUTXOTransaction(fromAddress, toAddress, uncompressedPubkey)

	chainId := big.NewInt(1337)
	signer := types.NewSigner(chainId, location)

	txHash := signer.Hash(tx)

	sig, err := schnorr.Sign(btcecKey, txHash[:])
	if err != nil {
		log.Fatalf("Failed to sign transaction: %v", err)
	}

	utxo := &types.UtxoTx{
		ChainID:   big.NewInt(1337),
		TxIn:      tx.TxIn(),
		TxOut:     tx.TxOut(),
		Signature: sig,
	}

	signedTx := types.NewTx(utxo)

	if !sig.Verify(txHash[:], btcecKey.PubKey()) {
		log.Fatal("Failed to verify signature")
	}

	rawUtxo := &types.UtxoTx{
		ChainID: chainId,
		TxIn:    tx.TxIn(),
		TxOut:   tx.TxOut(),
	}

	rawTx := types.NewTx(rawUtxo)

	txHash = signer.Hash(rawTx)

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
	outpointHash := common.HexToHash("0x0000055075e23c3a45f3e5df2bbd2fbc41f96ee348d02e3b44cff601d6b1060a")
	outpointIndex := uint32(0)

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

	return tx
}
