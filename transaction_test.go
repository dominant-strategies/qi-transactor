package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"log"
	"math/big"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcec/v2/schnorr/musig2"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	interfaces "github.com/dominant-strategies/go-quai"
	"github.com/dominant-strategies/go-quai/common"
	"github.com/dominant-strategies/go-quai/common/hexutil"
	"github.com/dominant-strategies/go-quai/core/types"
	"github.com/dominant-strategies/go-quai/crypto"
	"github.com/dominant-strategies/go-quai/params"
	"github.com/dominant-strategies/go-quai/quaiclient/ethclient"
	"github.com/holiman/uint256"
	"golang.org/x/crypto/sha3"
	"google.golang.org/protobuf/proto"
)

var (
	MAXFEE   = big.NewInt(1 * params.GWei)
	BASEFEE  = MAXFEE
	MINERTIP = big.NewInt(1 * params.GWei)
	GAS      = uint64(21000)
	VALUE    = big.NewInt(1)
	// Change the params to the proper chain config
	PARAMS              = params.Blake3PowLocalChainConfig
	wsUrlCyprus2        = "ws://127.0.0.1:8201"
	wsUrl_              = "ws://127.0.0.1:8200"
	qiAddr              = "0x00899DD5871a40E2c67d0645B8DcEb4Dc7974a59"
	qiPrivkey           = "0x383bd2269958a23e0391be01d255316363e2fa22269cbdc48052343346a4dcd8"
	quaiAddr            = "0x000D8BfADBF40241101c430D25151D893c6b16D8"
	quaiPrivkey         = "0x5eec99c44ec18c4b9e7136e259b58fa4879db568ff20245011de1f77af306e72"
	quaiGenAllocAddr    = "0x002a8cf994379232561556Da89C148eeec9539cd"
	quaiGenAllocPrivKey = "0xefdc32bef4218d3e5bae3858e45d4f18ed257c617bd8b7bae0939fae6f6bd6d6"
)

func TestSchnorrSignature(t *testing.T) {
	client, err := ethclient.Dial(wsUrl_)
	if err != nil {
		t.Fatalf("Failed to connect to the Ethereum WebSocket client: %v", err)
	}
	defer client.Close()
	//fromAddr := common.HexToAddress("0x01b55E4f6D014a3c54F95996C85842326ba37d61")
	privkey := common.FromHex("0x383bd2269958a23e0391be01d255316363e2fa22269cbdc48052343346a4dcd8")
	schnorrPrivKey, schnorrPubKey := btcec.PrivKeyFromBytes(privkey)

	toAddress := common.HexToAddress("0x00999DD5871a40E2c67d0645B8DcEb4Dc7974a59", location)
	outpointHash := common.HexToHash("0x00ac00bbead589f9338f02c5b1f9feabd1c0653aa600e5ef31380f27cdc2701c")
	outpointIndex := uint16(0)
	prevOut := types.OutPoint{outpointHash, outpointIndex}

	in := types.TxIn{
		PreviousOutPoint: prevOut,
		PubKey:           schnorrPubKey.SerializeUncompressed(),
	}

	newOut := types.TxOut{
		Denomination: 6,
		Address:      toAddress.Bytes(),
	}

	qiTx := &types.QiTx{
		ChainID: big.NewInt(1337),
		TxIn:    []types.TxIn{in},
		TxOut:   []types.TxOut{newOut},
	}

	signer := types.LatestSigner(PARAMS)
	txDigestHash := signer.Hash(types.NewTx(qiTx))
	sig, err := schnorr.Sign(schnorrPrivKey, txDigestHash[:])
	if err != nil {
		t.Errorf("Failed to sign transaction: %v", err)
		return
	}
	qiTx.Signature = sig
	fmt.Println("Signature: " + hexutil.Encode(qiTx.Signature.Serialize()))
	if !sig.Verify(txDigestHash[:], schnorrPubKey) {
		t.Error("Failed to verify signature")
		return
	}

	fmt.Println("Signed Raw Transaction")
	fmt.Println("Signature:", common.Bytes2Hex(sig.Serialize()))
	fmt.Println("TX Hash", types.NewTx(qiTx).Hash().String())
	fmt.Println("Pubkey", common.Bytes2Hex(qiTx.TxIn[0].PubKey))

	// Send the transaction
	err = client.SendTransaction(context.Background(), types.NewTx(qiTx))
	if err != nil {
		fmt.Println(err.Error())
		return
	}

}
func TestRecursiveHashing(t *testing.T) {
	now := time.Now()
	result := recursiveHash([]byte("hello"), 1000000)
	fmt.Println("Time taken: ", time.Since(now))
	fmt.Println("Result: ", hex.EncodeToString(result))
}

// recursiveHash performs a SHA3-256 hash on the input data n times recursively.
func recursiveHash(data []byte, n int) []byte {
	if n <= 0 {
		return data
	}
	// Hash the data using SHA3-256
	hash := sha3.Sum256(data)
	// Recursively hash the result
	return recursiveHash(hash[:], n-1)
}

func TestETXSchnorrSignature(t *testing.T) {
	client, err := ethclient.Dial(wsUrl_)
	if err != nil {
		t.Fatalf("Failed to connect to the Ethereum WebSocket client: %v", err)
	}
	defer client.Close()
	//fromAddr := common.HexToAddress("0x00899DD5871a40E2c67d0645B8DcEb4Dc7974a59")
	privkey := common.FromHex(qiPrivkey) //"383bd2269958a23e0391be01d255316363e2fa22269cbdc48052343346a4dcd8")
	schnorrPrivKey, schnorrPubKey := btcec.PrivKeyFromBytes(privkey)
	//0x625c4e3d17bbf9ad748d822b0359c36f52786198b58acd02fe05c207a600a0cdETXIndex:
	toAddress := common.HexToAddress("0x01b55E4f6D014a3c54F95996C85842326ba37d61", location)
	outpointHash := common.HexToHash("0x00e400f809f8bc19d2870a31854511b94d29b2ed96c3e638d454330fd4dcac1f")
	outpointIndex := uint16(0)
	prevOut := types.OutPoint{outpointHash, outpointIndex}

	in := types.TxIn{
		PreviousOutPoint: prevOut,
		PubKey:           schnorrPubKey.SerializeUncompressed(),
	}

	newOut := types.TxOut{
		Denomination: 1,
		Address:      toAddress.Bytes(),
	}

	qiTx := &types.QiTx{
		ChainID: big.NewInt(1337),
		TxIn:    []types.TxIn{in},
		TxOut:   []types.TxOut{newOut},
	}
	signer := types.LatestSigner(PARAMS)
	txDigestHash := signer.Hash(types.NewTx(qiTx))
	sig, err := schnorr.Sign(schnorrPrivKey, txDigestHash[:])
	if err != nil {
		t.Errorf("Failed to sign transaction: %v", err)
		return
	}
	qiTx.Signature = sig
	fmt.Println("Signature: " + hexutil.Encode(qiTx.Signature.Serialize()))
	if !sig.Verify(txDigestHash[:], schnorrPubKey) {
		t.Error("Failed to verify signature")
		return
	}

	fmt.Println("Signed Raw Transaction")
	fmt.Println("Signature:", common.Bytes2Hex(sig.Serialize()))
	fmt.Println("TX Digest Hash", txDigestHash.String())
	fmt.Println("Pubkey", common.Bytes2Hex(qiTx.TxIn[0].PubKey))
	fmt.Println("Tx hash: ", types.NewTx(qiTx).Hash().String())
	// Send the transaction
	err = client.SendTransaction(context.Background(), types.NewTx(qiTx))
	if err != nil {
		fmt.Println(err.Error())
		return
	}

}

func TestQiConversion(t *testing.T) {
	client, err := ethclient.Dial(wsUrl_)
	if err != nil {
		t.Fatalf("Failed to connect to the Ethereum WebSocket client: %v", err)
	}
	defer client.Close()
	//fromAddr := common.HexToAddress("0x00899DD5871a40E2c67d0645B8DcEb4Dc7974a59")
	privkey := common.FromHex(qiPrivkey) //"383bd2269958a23e0391be01d255316363e2fa22269cbdc48052343346a4dcd8")
	schnorrPrivKey, schnorrPubKey := btcec.PrivKeyFromBytes(privkey)
	//0x625c4e3d17bbf9ad748d822b0359c36f52786198b58acd02fe05c207a600a0cdETXIndex:
	toAddress := common.HexToAddress(quaiGenAllocAddr, location)
	outpointHash := common.HexToHash("1eb100e02d23e1793c2ac049033bc8ca47bebc27364e9f8fc657df43d2ba1e43")
	outpointIndex := uint16(0)
	prevOut := types.OutPoint{outpointHash, outpointIndex}

	in := types.TxIn{
		PreviousOutPoint: prevOut,
		PubKey:           schnorrPubKey.SerializeUncompressed(),
	}

	newOut := types.TxOut{
		Denomination: 6,
		Address:      toAddress.Bytes(),
	}
	newOut2 := types.TxOut{
		Denomination: 5,
		Address:      toAddress.Bytes(),
	}

	qiTx := &types.QiTx{
		ChainID: big.NewInt(1337),
		TxIn:    []types.TxIn{in},
		TxOut:   []types.TxOut{newOut, newOut2},
	}
	signer := types.LatestSigner(PARAMS)
	txDigestHash := signer.Hash(types.NewTx(qiTx))
	sig, err := schnorr.Sign(schnorrPrivKey, txDigestHash[:])
	if err != nil {
		t.Errorf("Failed to sign transaction: %v", err)
		return
	}
	qiTx.Signature = sig
	fmt.Println("Signature: " + hexutil.Encode(qiTx.Signature.Serialize()))
	if !sig.Verify(txDigestHash[:], schnorrPubKey) {
		t.Error("Failed to verify signature")
		return
	}

	fmt.Println("Signed Raw Transaction")
	fmt.Println("Signature:", common.Bytes2Hex(sig.Serialize()))
	fmt.Println("TX Digest Hash", txDigestHash.String())
	fmt.Println("Pubkey", common.Bytes2Hex(qiTx.TxIn[0].PubKey))

	// Send the transaction
	err = client.SendTransaction(context.Background(), types.NewTx(qiTx))
	if err != nil {
		fmt.Println(err.Error())
		return
	}

}

func TestRedeemQuai(t *testing.T) {
	client, err := ethclient.Dial(wsUrl_)
	if err != nil {
		t.Fatalf("Failed to connect to the Ethereum WebSocket client: %v", err)
	}
	defer client.Close()
	fromAddress := common.HexToAddress(quaiGenAllocAddr, location)
	privKey, err := crypto.ToECDSA(common.FromHex(quaiGenAllocPrivKey))
	if err != nil {
		t.Fatalf("Failed to convert private key to ECDSA: %v", err)
	}
	from := crypto.PubkeyToAddress(privKey.PublicKey, location)
	if !from.Equal(fromAddress) {
		t.Fatalf("Failed to convert public key to address: %v", err)
	}
	toAddr := common.HexToAddress(fmt.Sprintf("0x%x0000000000000000000000000000000000000A", location.BytePrefix()), location)
	fmt.Println("To Address: ", toAddr.String())
	signer := types.LatestSigner(PARAMS)
	nonce, err := client.PendingNonceAt(context.Background(), from.MixedcaseAddress())
	if err != nil {
		t.Error(err.Error())
		t.Fail()
	}
	// Check balance
	balance, err := client.BalanceAt(context.Background(), fromAddress.MixedcaseAddress(), nil)
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	fmt.Println("Balance: ", balance)
	fmt.Println("Nonce: ", nonce)
	inner_tx := types.QuaiTx{ChainID: PARAMS.ChainID, Nonce: nonce, GasTipCap: MINERTIP, GasFeeCap: BASEFEE, Gas: GAS * 10, To: &toAddr, Value: common.Big0, Data: nil, AccessList: types.AccessList{}}

	tx := types.NewTx(&inner_tx)
	tx, err = types.SignTx(tx, signer, privKey)
	if err != nil {
		t.Error(err.Error())
		t.Fail()
		return
	}
	/*accessList, err := client.CreateAccessList(context.Background(), interfaces.CallMsg{From: fromAddress, To: &toAddr, Data: nil})
	if err != nil {
		t.Error(err.Error())
		t.Fail()
		return
	}
	fmt.Printf("AccessList: %+v\n", accessList)*/
	err = client.SendTransaction(context.Background(), tx)
	if err != nil {
		t.Error(err.Error())
		t.Fail()
		return
	}
	tx, isPending, err := client.TransactionByHash(context.Background(), tx.Hash(location...))
	fmt.Printf("tx: %+v isPending: %v err: %v\n", tx, isPending, err)
	receipt, err := client.TransactionReceipt(context.Background(), tx.Hash())
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	fmt.Printf("Receipt: %+v\n", receipt)
	nonce, err = client.PendingNonceAt(context.Background(), from.MixedcaseAddress())
	if err != nil {
		t.Error(err.Error())
		t.Fail()
	}
	// Check balance
	balance, err = client.BalanceAt(context.Background(), fromAddress.MixedcaseAddress(), nil)
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	fmt.Println("Balance: ", balance)
	fmt.Println("Nonce: ", nonce)
}

func TestQuaiConversion(t *testing.T) {
	fromAddress := common.HexToAddress(quaiGenAllocAddr, location)
	privKey, err := crypto.ToECDSA(common.FromHex(quaiGenAllocPrivKey))
	if err != nil {
		t.Fatalf("Failed to convert private key to ECDSA: %v", err)
	}
	from := crypto.PubkeyToAddress(privKey.PublicKey, location)
	if !from.Equal(fromAddress) {
		t.Fatalf("Failed to convert public key to address: %v", err)
	}
	toAddress := common.HexToAddress("0x00e8c50233D309e5e63805D6d7AE10e6EDE83c65", location)
	toPrivKey, err := crypto.ToECDSA(common.FromHex("0x2f156531b49753994351ae3cb446264993dcdb21276558ff9f4126d6129ea21c"))
	if err != nil {
		t.Fatalf("Failed to convert private key to ECDSA: %v", err)
	}
	to := crypto.PubkeyToAddress(toPrivKey.PublicKey, location)
	if !to.Equal(toAddress) {
		t.Fatalf("Failed to convert public key to address: %v", err)
	}
	signer := types.LatestSigner(PARAMS)

	client, err := ethclient.Dial(wsUrl_)
	if err != nil {
		t.Fatalf("Failed to connect to the Ethereum WebSocket client: %v", err)
	}
	defer client.Close()

	nonce, err := client.PendingNonceAt(context.Background(), from.MixedcaseAddress())
	if err != nil {
		t.Error(err.Error())
		t.Fail()
	}
	// Check balance
	balance, err := client.BalanceAt(context.Background(), fromAddress.MixedcaseAddress(), nil)
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	fmt.Println("Balance: ", balance)
	fmt.Println("Nonce: ", nonce)

	inner_tx := types.QuaiTx{ChainID: PARAMS.ChainID, Nonce: nonce, GasTipCap: MINERTIP, GasFeeCap: BASEFEE, Gas: GAS * 10, To: &to, Value: big.NewInt(params.Ether), Data: nil, AccessList: types.AccessList{}}
	tx := types.NewTx(&inner_tx)
	tx, err = types.SignTx(tx, signer, privKey)
	if err != nil {
		t.Error(err.Error())
		t.Fail()
		return
	}

	err = client.SendTransaction(context.Background(), tx)
	if err != nil {
		t.Error(err.Error())
		t.Fail()
		return
	}
	//time.Sleep(60 * time.Second)
	tx, isPending, err := client.TransactionByHash(context.Background(), tx.Hash(location...))
	fmt.Printf("tx: %+v isPending: %v err: %v\n", tx, isPending, err)
	receipt, err := client.TransactionReceipt(context.Background(), tx.Hash())
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	fmt.Printf("Receipt: %+v\n", receipt)

	etx := receipt.Etxs[0]
	tx, isPending, err = client.TransactionByHash(context.Background(), etx.Hash())
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	fmt.Printf("etx: %+v isPending: %v err: %v\n", tx, isPending, err)
	receipt, err = client.TransactionReceipt(context.Background(), etx.Hash())
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	fmt.Printf("ETX Receipt: %+v\n", receipt)
}

func TestETX(t *testing.T) {
	fromAddress := common.HexToAddress("0x000D8BfADBF40241101c430D25151D893c6b16D8", location)
	privKey, err := crypto.ToECDSA(common.FromHex(quaiPrivkey))
	if err != nil {
		t.Fatalf("Failed to convert private key to ECDSA: %v", err)
	}
	from := crypto.PubkeyToAddress(privKey.PublicKey, location)
	if !from.Equal(fromAddress) {
		t.Fatalf("Failed to convert public key to address: %v", err)
	}

	toAddress := common.HexToAddress("0x0109E949aF137F98bb6AF72102b9fE5C3d7e17cc", location)
	toPrivKey, err := crypto.ToECDSA(common.FromHex("0x090fb448d46419ff13b6ee340f480623fd63e208b7bee788e79f35c63e428c3f"))
	if err != nil {
		t.Fatalf("Failed to convert private key to ECDSA: %v", err)
	}
	to := crypto.PubkeyToAddress(toPrivKey.PublicKey, location)
	if !to.Equal(toAddress) {
		t.Fatalf("Failed to convert public key to address: %v", err)
	}

	signer := types.LatestSigner(PARAMS)

	client, err := ethclient.Dial(wsUrl_)
	if err != nil {
		t.Fatalf("Failed to connect to the Ethereum WebSocket client: %v", err)
	}
	defer client.Close()
	cyprus2Client, err := ethclient.Dial(wsUrlCyprus2)
	if err != nil {
		t.Fatalf("Failed to connect to the Ethereum WebSocket client: %v", err)
	}
	defer cyprus2Client.Close()
	nonce, err := client.PendingNonceAt(context.Background(), from.MixedcaseAddress())
	if err != nil {
		t.Error(err.Error())
		t.Fail()
	}
	// Check balance
	balance, err := client.BalanceAt(context.Background(), fromAddress.MixedcaseAddress(), nil)
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	fmt.Println("Balance: ", balance)
	fmt.Println("Nonce: ", nonce)

	inner_tx := types.QuaiTx{ChainID: PARAMS.ChainID, Nonce: nonce, GasTipCap: MINERTIP, GasFeeCap: BASEFEE, Gas: GAS * 3, To: &to, Value: VALUE, Data: nil, AccessList: types.AccessList{}}
	tx := types.NewTx(&inner_tx)

	tx, err = types.SignTx(tx, signer, privKey)
	if err != nil {
		t.Error(err.Error())
		t.Fail()
		return
	}

	err = client.SendTransaction(context.Background(), tx)
	if err != nil {
		t.Error(err.Error())
		t.Fail()
		return
	}

	tx, isPending, err := client.TransactionByHash(context.Background(), tx.Hash(location...))
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	fmt.Printf("tx: %+v isPending: %v err: %v\n", tx, isPending, err)
	receipt, err := client.TransactionReceipt(context.Background(), tx.Hash())
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	fmt.Printf("Receipt: %+v\n", receipt)

	etx := receipt.Etxs[0]
	tx, isPending, err = cyprus2Client.TransactionByHash(context.Background(), etx.Hash())
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	fmt.Printf("etx: %+v isPending: %v err: %v\n", tx, isPending, err)
	receipt, err = cyprus2Client.TransactionReceipt(context.Background(), etx.Hash())
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	fmt.Printf("ETX Receipt: %+v\n", receipt)
	balance2, err := cyprus2Client.BalanceAt(context.Background(), toAddress.MixedcaseAddress(), nil)
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	fmt.Println("Balance2: ", balance2)

}

func TestETXs(t *testing.T) {
	client, err := ethclient.Dial(wsUrl_)
	if err != nil {
		t.Fatalf("Failed to connect to the Ethereum WebSocket client: %v", err)
	}
	defer client.Close()

	for i := 0; i < 1000; i++ {
		fromAddress := common.HexToAddress(quaiGenAllocAddr, location)
		privKey, err := crypto.ToECDSA(common.FromHex(quaiGenAllocPrivKey))
		if err != nil {
			t.Fatalf("Failed to convert private key to ECDSA: %v", err)
		}
		from := crypto.PubkeyToAddress(privKey.PublicKey, location)
		if !from.Equal(fromAddress) {
			t.Fatalf("Failed to convert public key to address: %v", err)
		}

		toAddress := common.HexToAddress("0x1109E949aF137F98bb6AF72102b9fE5C3d7e17cc", location)
		signer := types.LatestSigner(PARAMS)

		nonce, err := client.PendingNonceAt(context.Background(), from.MixedcaseAddress())
		if err != nil {
			t.Error(err.Error())
			t.Fail()
		}
		// Check balance
		balance, err := client.BalanceAt(context.Background(), fromAddress.MixedcaseAddress(), nil)
		if err != nil {
			fmt.Println(err.Error())
			return
		}
		fmt.Println("Balance: ", balance)
		fmt.Println("Nonce: ", nonce)

		inner_tx := types.QuaiTx{ChainID: PARAMS.ChainID, Nonce: nonce, GasTipCap: MINERTIP, GasFeeCap: BASEFEE, Gas: GAS * 3, To: &toAddress, Value: VALUE, Data: nil, AccessList: types.AccessList{}}
		tx := types.NewTx(&inner_tx)

		tx, err = types.SignTx(tx, signer, privKey)
		if err != nil {
			t.Error(err.Error())
			t.Fail()
			return
		}

		err = client.SendTransaction(context.Background(), tx)
		if err != nil {
			if strings.Contains(err.Error(), "already known") || strings.Contains(err.Error(), "nonce too low") {
				t.Log("Sent TX ", i)
				time.Sleep(1 * time.Second)
				continue
			}
			t.Error(err.Error())
			t.Fail()
			return
		}
		t.Log("Sent TX ", i)
		time.Sleep(500 * time.Millisecond)
	}
}

// ERC20X.sol Contract bytecode
var binary = "60806040523480156200001157600080fd5b506040518060400160405280601681526020017f517561692043726f73732d436861696e20546f6b656e00000000000000000000815250600f90816200005891906200096d565b506040518060400160405280600381526020017f5158430000000000000000000000000000000000000000000000000000000000815250601090816200009f91906200096d565b5033601160006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff1602179055506000683635c9adc5dea00000905062000123601160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff16826200057c60201b60201c565b6040518060400160405280600060ff168152602001601d60ff1681525060126000600d811062000158576200015762000a54565b5b0160008201518160000160006101000a81548160ff021916908360ff16021790555060208201518160000160016101000a81548160ff021916908360ff1602179055509050506040518060400160405280601e60ff168152602001603a60ff1681525060126001600d8110620001d357620001d262000a54565b5b0160008201518160000160006101000a81548160ff021916908360ff16021790555060208201518160000160016101000a81548160ff021916908360ff1602179055509050506040518060400160405280603b60ff168152602001605760ff1681525060126002600d81106200024e576200024d62000a54565b5b0160008201518160000160006101000a81548160ff021916908360ff16021790555060208201518160000160016101000a81548160ff021916908360ff1602179055509050506040518060400160405280605860ff168152602001607360ff1681525060126003600d8110620002c957620002c862000a54565b5b0160008201518160000160006101000a81548160ff021916908360ff16021790555060208201518160000160016101000a81548160ff021916908360ff1602179055509050506040518060400160405280607460ff168152602001608f60ff1681525060126004600d811062000344576200034362000a54565b5b0160008201518160000160006101000a81548160ff021916908360ff16021790555060208201518160000160016101000a81548160ff021916908360ff1602179055509050506040518060400160405280609060ff16815260200160ab60ff1681525060126005600d8110620003bf57620003be62000a54565b5b0160008201518160000160006101000a81548160ff021916908360ff16021790555060208201518160000160016101000a81548160ff021916908360ff160217905550905050604051806040016040528060ac60ff16815260200160c760ff1681525060126006600d81106200043a576200043962000a54565b5b0160008201518160000160006101000a81548160ff021916908360ff16021790555060208201518160000160016101000a81548160ff021916908360ff160217905550905050604051806040016040528060c860ff16815260200160e360ff1681525060126007600d8110620004b557620004b462000a54565b5b0160008201518160000160006101000a81548160ff021916908360ff16021790555060208201518160000160016101000a81548160ff021916908360ff160217905550905050604051806040016040528060e460ff16815260200160ff801681525060126008600d81106200052f576200052e62000a54565b5b0160008201518160000160006101000a81548160ff021916908360ff16021790555060208201518160000160016101000a81548160ff021916908360ff1602179055509050505062000b9e565b600073ffffffffffffffffffffffffffffffffffffffff168273ffffffffffffffffffffffffffffffffffffffff1603620005ee576040517f08c379a0000000000000000000000000000000000000000000000000000000008152600401620005e59062000ae4565b60405180910390fd5b6200060260008383620006e960201b60201c565b80600e600082825462000616919062000b35565b92505081905550806000808473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020600082825401925050819055508173ffffffffffffffffffffffffffffffffffffffff16600073ffffffffffffffffffffffffffffffffffffffff167fddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef83604051620006c9919062000b81565b60405180910390a3620006e560008383620006ee60201b60201c565b5050565b505050565b505050565b600081519050919050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052604160045260246000fd5b7f4e487b7100000000000000000000000000000000000000000000000000000000600052602260045260246000fd5b600060028204905060018216806200077557607f821691505b6020821081036200078b576200078a6200072d565b5b50919050565b60008190508160005260206000209050919050565b60006020601f8301049050919050565b600082821b905092915050565b600060088302620007f57fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff82620007b6565b620008018683620007b6565b95508019841693508086168417925050509392505050565b6000819050919050565b6000819050919050565b60006200084e62000848620008428462000819565b62000823565b62000819565b9050919050565b6000819050919050565b6200086a836200082d565b62000882620008798262000855565b848454620007c3565b825550505050565b600090565b620008996200088a565b620008a68184846200085f565b505050565b5b81811015620008ce57620008c26000826200088f565b600181019050620008ac565b5050565b601f8211156200091d57620008e78162000791565b620008f284620007a6565b8101602085101562000902578190505b6200091a6200091185620007a6565b830182620008ab565b50505b505050565b600082821c905092915050565b6000620009426000198460080262000922565b1980831691505092915050565b60006200095d83836200092f565b9150826002028217905092915050565b6200097882620006f3565b67ffffffffffffffff811115620009945762000993620006fe565b5b620009a082546200075c565b620009ad828285620008d2565b600060209050601f831160018114620009e55760008415620009d0578287015190505b620009dc85826200094f565b86555062000a4c565b601f198416620009f58662000791565b60005b8281101562000a1f57848901518255600182019150602085019450602081019050620009f8565b8683101562000a3f578489015162000a3b601f8916826200092f565b8355505b6001600288020188555050505b505050505050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052603260045260246000fd5b600082825260208201905092915050565b7f45524332303a206d696e7420746f20746865207a65726f206164647265737300600082015250565b600062000acc601f8362000a83565b915062000ad98262000a94565b602082019050919050565b6000602082019050818103600083015262000aff8162000abd565b9050919050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052601160045260246000fd5b600062000b428262000819565b915062000b4f8362000819565b925082820190508082111562000b6a5762000b6962000b06565b5b92915050565b62000b7b8162000819565b82525050565b600060208201905062000b98600083018462000b70565b92915050565b61320b8062000bae6000396000f3fe6080604052600436106101145760003560e01c8063593b79fe116100a0578063a534d9de11610064578063a534d9de146103f3578063a9059cbb1461041c578063bc472aa314610459578063dd62ed3e14610496578063e20e50ba146104d357610114565b8063593b79fe146102f557806370a082311461033257806373cddab21461036f57806395d89b411461038b578063a457c2d7146103b657610114565b806323b872dd116100e757806323b872dd146101d5578063313ce56714610212578063395093511461023d578063399444bc1461027a578063429437bf146102b757610114565b806306fdde0314610119578063095ea7b31461014457806318160ddd1461018157806320e8dd93146101ac575b600080fd5b34801561012557600080fd5b5061012e6104fc565b60405161013b9190611cf4565b60405180910390f35b34801561015057600080fd5b5061016b60048036038101906101669190611db4565b61058e565b6040516101789190611e0f565b60405180910390f35b34801561018d57600080fd5b506101966105a5565b6040516101a39190611e39565b60405180910390f35b3480156101b857600080fd5b506101d360048036038101906101ce9190611db4565b6105af565b005b3480156101e157600080fd5b506101fc60048036038101906101f79190611e54565b6106ad565b6040516102099190611e0f565b60405180910390f35b34801561021e57600080fd5b506102276106d0565b6040516102349190611ec3565b60405180910390f35b34801561024957600080fd5b50610264600480360381019061025f9190611db4565b6106d9565b6040516102719190611e0f565b60405180910390f35b34801561028657600080fd5b506102a1600480360381019061029c9190611ede565b610709565b6040516102ae9190611ec3565b60405180910390f35b3480156102c357600080fd5b506102de60048036038101906102d99190611f0b565b610816565b6040516102ec929190611f38565b60405180910390f35b34801561030157600080fd5b5061031c60048036038101906103179190611ede565b610857565b6040516103299190611fb6565b60405180910390f35b34801561033e57600080fd5b5061035960048036038101906103549190611ede565b610880565b6040516103669190611e39565b60405180910390f35b61038960048036038101906103849190611fd8565b6108c8565b005b34801561039757600080fd5b506103a0610b71565b6040516103ad9190611cf4565b60405180910390f35b3480156103c257600080fd5b506103dd60048036038101906103d89190611db4565b610c03565b6040516103ea9190611e0f565b60405180910390f35b3480156103ff57600080fd5b5061041a6004803603810190610415919061210e565b610c73565b005b34801561042857600080fd5b50610443600480360381019061043e9190611db4565b610f62565b6040516104509190611e0f565b60405180910390f35b34801561046557600080fd5b50610480600480360381019061047b9190611f0b565b610f79565b60405161048d919061219e565b60405180910390f35b3480156104a257600080fd5b506104bd60048036038101906104b891906121b9565b610faf565b6040516104ca9190611e39565b60405180910390f35b3480156104df57600080fd5b506104fa60048036038101906104f59190612225565b611036565b005b6060600f805461050b90612294565b80601f016020809104026020016040519081016040528092919081815260200182805461053790612294565b80156105845780601f1061055957610100808354040283529160200191610584565b820191906000526020600020905b81548152906001019060200180831161056757829003601f168201915b5050505050905090565b600061059b338484611256565b6001905092915050565b6000600e54905090565b3373ffffffffffffffffffffffffffffffffffffffff1660026105d133610709565b60ff16600c81106105e5576105e46122c5565b5b0160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16143360405160200161062f919061233c565b60405160208183030381529060405260405160200161064e9190612436565b6040516020818303038152906040529061069e576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004016106959190611cf4565b60405180910390fd5b506106a98282611466565b5050565b60006106ba8433846115bc565b6106c5848484611648565b600190509392505050565b60006012905090565b6000803390506106fe8185856106ef8589610faf565b6106f99190612492565b611256565b600191505092915050565b60008061071583610857565b600081518110610728576107276122c5565b5b602001015160f81c60f81b60f81c905060005b60098160ff1610156107d55760128160ff16600d811061075e5761075d6122c5565b5b0160000160009054906101000a900460ff1660ff168260ff16101580156107b3575060128160ff16600d8110610797576107966122c5565b5b0160000160019054906101000a900460ff1660ff168260ff1611155b156107c2578092505050610811565b80806107cd906124c6565b91505061073b565b506040517f08c379a00000000000000000000000000000000000000000000000000000000081526004016108089061253b565b60405180910390fd5b919050565b601281600d811061082657600080fd5b016000915090508060000160009054906101000a900460ff16908060000160019054906101000a900460ff16905082565b60608160405160200161086a919061233c565b6040516020818303038152906040529050919050565b60008060008373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020549050919050565b600085f79050801561090f576040517f08c379a0000000000000000000000000000000000000000000000000000000008152600401610906906125a7565b60405180910390fd5b6109193386611905565b6000600261092688610709565b60ff16600c811061093a576109396122c5565b5b0160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff169050600073ffffffffffffffffffffffffffffffffffffffff168173ffffffffffffffffffffffffffffffffffffffff16036109cd576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004016109c490612639565b60405180910390fd5b60008585856109dc9190612492565b6109e69190612659565b9050803410156109f582611ad2565b604051602001610a05919061278a565b60405160208183030381529060405290610a55576040517f08c379a0000000000000000000000000000000000000000000000000000000008152600401610a4c9190611cf4565b60405180910390fd5b5060008888604051602401610a6b9291906127b7565b6040516020818303038152906040527f20e8dd93000000000000000000000000000000000000000000000000000000007bffffffffffffffffffffffffffffffffffffffffffffffffffffffff19166020820180517bffffffffffffffffffffffffffffffffffffffffffffffffffffffff838183161783525050505090506000806000835160208501898b8d60008b6000f690508973ffffffffffffffffffffffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff167fcf0ee562475620bbcd2f1b0675c8163317513271e4fdbbe9722436f247bd6d998b604051610b5d9190611e39565b60405180910390a350505050505050505050565b606060108054610b8090612294565b80601f0160208091040260200160405190810160405280929190818152602001828054610bac90612294565b8015610bf95780601f10610bce57610100808354040283529160200191610bf9565b820191906000526020600020905b815481529060010190602001808311610bdc57829003601f168201915b5050505050905090565b6000803390506000610c158286610faf565b905083811015610c5a576040517f08c379a0000000000000000000000000000000000000000000000000000000008152600401610c5190612852565b60405180910390fd5b610c678286868403611256565b60019250505092915050565b601160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff1614610d03576040517f08c379a0000000000000000000000000000000000000000000000000000000008152600401610cfa906128be565b60405180910390fd5b818190508484905014610d4b576040517f08c379a0000000000000000000000000000000000000000000000000000000008152600401610d4290612950565b60405180910390fd5b60005b848490508160ff161015610f5b57600985858360ff16818110610d7457610d736122c5565b5b9050602002016020810190610d899190612970565b60ff1610610dcc576040517f08c379a0000000000000000000000000000000000000000000000000000000008152600401610dc3906129e9565b60405180910390fd5b600073ffffffffffffffffffffffffffffffffffffffff16600286868460ff16818110610dfc57610dfb6122c5565b5b9050602002016020810190610e119190612970565b60ff16600c8110610e2557610e246122c5565b5b0160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1614610e9d576040517f08c379a0000000000000000000000000000000000000000000000000000000008152600401610e9490612a7b565b60405180910390fd5b82828260ff16818110610eb357610eb26122c5565b5b9050602002016020810190610ec89190611ede565b600286868460ff16818110610ee057610edf6122c5565b5b9050602002016020810190610ef59190612970565b60ff16600c8110610f0957610f086122c5565b5b0160006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff1602179055508080610f53906124c6565b915050610d4e565b5050505050565b6000610f6f338484611648565b6001905092915050565b600281600c8110610f8957600080fd5b016000915054906101000a900473ffffffffffffffffffffffffffffffffffffffff1681565b6000600160008473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060008373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002054905092915050565b600081f79050801561107d576040517f08c379a0000000000000000000000000000000000000000000000000000000008152600401611074906125a7565b60405180910390fd5b601160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff161461110d576040517f08c379a0000000000000000000000000000000000000000000000000000000008152600401611104906128be565b60405180910390fd5b60098360ff1610611153576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040161114a906129e9565b60405180910390fd5b600073ffffffffffffffffffffffffffffffffffffffff1660028460ff16600c8110611182576111816122c5565b5b0160009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16146111fa576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004016111f190612a7b565b60405180910390fd5b8160028460ff16600c8110611212576112116122c5565b5b0160006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff160217905550505050565b600082f790508061129c576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040161129390612b0d565b60405180910390fd5b600073ffffffffffffffffffffffffffffffffffffffff168473ffffffffffffffffffffffffffffffffffffffff160361130b576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040161130290612b9f565b60405180910390fd5b600073ffffffffffffffffffffffffffffffffffffffff168373ffffffffffffffffffffffffffffffffffffffff160361137a576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040161137190612c31565b60405180910390fd5b81600160008673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060008573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020819055508273ffffffffffffffffffffffffffffffffffffffff168473ffffffffffffffffffffffffffffffffffffffff167f8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925846040516114589190611e39565b60405180910390a350505050565b600073ffffffffffffffffffffffffffffffffffffffff168273ffffffffffffffffffffffffffffffffffffffff16036114d5576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004016114cc90612c9d565b60405180910390fd5b6114e160008383611c5a565b80600e60008282546114f39190612492565b92505081905550806000808473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020600082825401925050819055508173ffffffffffffffffffffffffffffffffffffffff16600073ffffffffffffffffffffffffffffffffffffffff167fddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef836040516115a49190611e39565b60405180910390a36115b860008383611c5f565b5050565b60006115c88484610faf565b90507fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff81146116425781811015611634576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040161162b90612d09565b60405180910390fd5b6116418484848403611256565b5b50505050565b600082f790508061168e576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040161168590612d9b565b60405180910390fd5b600073ffffffffffffffffffffffffffffffffffffffff168473ffffffffffffffffffffffffffffffffffffffff16036116fd576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004016116f490612e2d565b60405180910390fd5b600073ffffffffffffffffffffffffffffffffffffffff168373ffffffffffffffffffffffffffffffffffffffff160361176c576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040161176390612ebf565b60405180910390fd5b611777848484611c5a565b60008060008673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020549050828110156117fd576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004016117f490612f51565b60405180910390fd5b8281036000808773ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002081905550826000808673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020600082825401925050819055508373ffffffffffffffffffffffffffffffffffffffff168573ffffffffffffffffffffffffffffffffffffffff167fddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef856040516118eb9190611e39565b60405180910390a36118fe858585611c5f565b5050505050565b600073ffffffffffffffffffffffffffffffffffffffff168273ffffffffffffffffffffffffffffffffffffffff1603611974576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040161196b90612fe3565b60405180910390fd5b61198082600083611c5a565b60008060008473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002054905081811015611a06576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004016119fd90613075565b60405180910390fd5b8181036000808573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000208190555081600e60008282540392505081905550600073ffffffffffffffffffffffffffffffffffffffff168373ffffffffffffffffffffffffffffffffffffffff167fddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef84604051611ab99190611e39565b60405180910390a3611acd83600084611c5f565b505050565b606060008203611b19576040518060400160405280600181526020017f30000000000000000000000000000000000000000000000000000000000000008152509050611c55565b600082905060005b60008214611b4b578080611b3490613095565b915050600a82611b44919061310c565b9150611b21565b60008167ffffffffffffffff811115611b6757611b6661313d565b5b6040519080825280601f01601f191660200182016040528015611b995781602001600182028036833780820191505090505b50905060008290505b60008614611c4d57600181611bb7919061316c565b90506000600a8088611bc9919061310c565b611bd39190612659565b87611bde919061316c565b6030611bea91906131a0565b905060008160f81b905080848481518110611c0857611c076122c5565b5b60200101907effffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff1916908160001a905350600a88611c44919061310c565b97505050611ba2565b819450505050505b919050565b505050565b505050565b600081519050919050565b600082825260208201905092915050565b60005b83811015611c9e578082015181840152602081019050611c83565b60008484015250505050565b6000601f19601f8301169050919050565b6000611cc682611c64565b611cd08185611c6f565b9350611ce0818560208601611c80565b611ce981611caa565b840191505092915050565b60006020820190508181036000830152611d0e8184611cbb565b905092915050565b600080fd5b600080fd5b600073ffffffffffffffffffffffffffffffffffffffff82169050919050565b6000611d4b82611d20565b9050919050565b611d5b81611d40565b8114611d6657600080fd5b50565b600081359050611d7881611d52565b92915050565b6000819050919050565b611d9181611d7e565b8114611d9c57600080fd5b50565b600081359050611dae81611d88565b92915050565b60008060408385031215611dcb57611dca611d16565b5b6000611dd985828601611d69565b9250506020611dea85828601611d9f565b9150509250929050565b60008115159050919050565b611e0981611df4565b82525050565b6000602082019050611e246000830184611e00565b92915050565b611e3381611d7e565b82525050565b6000602082019050611e4e6000830184611e2a565b92915050565b600080600060608486031215611e6d57611e6c611d16565b5b6000611e7b86828701611d69565b9350506020611e8c86828701611d69565b9250506040611e9d86828701611d9f565b9150509250925092565b600060ff82169050919050565b611ebd81611ea7565b82525050565b6000602082019050611ed86000830184611eb4565b92915050565b600060208284031215611ef457611ef3611d16565b5b6000611f0284828501611d69565b91505092915050565b600060208284031215611f2157611f20611d16565b5b6000611f2f84828501611d9f565b91505092915050565b6000604082019050611f4d6000830185611eb4565b611f5a6020830184611eb4565b9392505050565b600081519050919050565b600082825260208201905092915050565b6000611f8882611f61565b611f928185611f6c565b9350611fa2818560208601611c80565b611fab81611caa565b840191505092915050565b60006020820190508181036000830152611fd08184611f7d565b905092915050565b600080600080600060a08688031215611ff457611ff3611d16565b5b600061200288828901611d69565b955050602061201388828901611d9f565b945050604061202488828901611d9f565b935050606061203588828901611d9f565b925050608061204688828901611d9f565b9150509295509295909350565b600080fd5b600080fd5b600080fd5b60008083601f84011261207857612077612053565b5b8235905067ffffffffffffffff81111561209557612094612058565b5b6020830191508360208202830111156120b1576120b061205d565b5b9250929050565b60008083601f8401126120ce576120cd612053565b5b8235905067ffffffffffffffff8111156120eb576120ea612058565b5b6020830191508360208202830111156121075761210661205d565b5b9250929050565b6000806000806040858703121561212857612127611d16565b5b600085013567ffffffffffffffff81111561214657612145611d1b565b5b61215287828801612062565b9450945050602085013567ffffffffffffffff81111561217557612174611d1b565b5b612181878288016120b8565b925092505092959194509250565b61219881611d40565b82525050565b60006020820190506121b3600083018461218f565b92915050565b600080604083850312156121d0576121cf611d16565b5b60006121de85828601611d69565b92505060206121ef85828601611d69565b9150509250929050565b61220281611ea7565b811461220d57600080fd5b50565b60008135905061221f816121f9565b92915050565b6000806040838503121561223c5761223b611d16565b5b600061224a85828601612210565b925050602061225b85828601611d69565b9150509250929050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052602260045260246000fd5b600060028204905060018216806122ac57607f821691505b6020821081036122bf576122be612265565b5b50919050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052603260045260246000fd5b60008160601b9050919050565b600061230c826122f4565b9050919050565b600061231e82612301565b9050919050565b61233661233182611d40565b612313565b82525050565b60006123488284612325565b60148201915081905092915050565b600081905092915050565b7f53656e6465722000000000000000000000000000000000000000000000000000600082015250565b6000612398600783612357565b91506123a382612362565b600782019050919050565b600081905092915050565b60006123c482611f61565b6123ce81856123ae565b93506123de818560208601611c80565b80840191505092915050565b7f206e6f7420617070726f76656400000000000000000000000000000000000000600082015250565b6000612420600d83612357565b915061242b826123ea565b600d82019050919050565b60006124418261238b565b915061244d82846123b9565b915061245882612413565b915081905092915050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052601160045260246000fd5b600061249d82611d7e565b91506124a883611d7e565b92508282019050808211156124c0576124bf612463565b5b92915050565b60006124d182611ea7565b915060ff82036124e4576124e3612463565b5b600182019050919050565b7f496e76616c6964204c6f636174696f6e00000000000000000000000000000000600082015250565b6000612525601083611c6f565b9150612530826124ef565b602082019050919050565b6000602082019050818103600083015261255481612518565b9050919050565b7f41646472657373206973206e6f742065787465726e616c000000000000000000600082015250565b6000612591601783611c6f565b915061259c8261255b565b602082019050919050565b600060208201905081810360008301526125c081612584565b9050919050565b7f546f6b656e206973206e6f7420617661696c61626c65206f6e2074686520646560008201527f7374696e6174696f6e20636861696e0000000000000000000000000000000000602082015250565b6000612623602f83611c6f565b915061262e826125c7565b604082019050919050565b6000602082019050818103600083015261265281612616565b9050919050565b600061266482611d7e565b915061266f83611d7e565b925082820261267d81611d7e565b9150828204841483151761269457612693612463565b5b5092915050565b7f4e6f7420656e6f756768206761732073656e742c206e656564206174206c656160008201527f7374200000000000000000000000000000000000000000000000000000000000602082015250565b60006126f7602383612357565b91506127028261269b565b602382019050919050565b600061271882611c64565b6127228185612357565b9350612732818560208601611c80565b80840191505092915050565b7f2077656900000000000000000000000000000000000000000000000000000000600082015250565b6000612774600483612357565b915061277f8261273e565b600482019050919050565b6000612795826126ea565b91506127a1828461270d565b91506127ac82612767565b915081905092915050565b60006040820190506127cc600083018561218f565b6127d96020830184611e2a565b9392505050565b7f45524332303a2064656372656173656420616c6c6f77616e63652062656c6f7760008201527f207a65726f000000000000000000000000000000000000000000000000000000602082015250565b600061283c602583611c6f565b9150612847826127e0565b604082019050919050565b6000602082019050818103600083015261286b8161282f565b9050919050565b7f53656e646572206973206e6f74206465706c6f79657200000000000000000000600082015250565b60006128a8601683611c6f565b91506128b382612872565b602082019050919050565b600060208201905081810360008301526128d78161289b565b9050919050565b7f636861696e20616e64206164647265737320617272617973206d75737420626560008201527f207468652073616d65206c656e67746800000000000000000000000000000000602082015250565b600061293a603083611c6f565b9150612945826128de565b604082019050919050565b600060208201905081810360008301526129698161292d565b9050919050565b60006020828403121561298657612985611d16565b5b600061299484828501612210565b91505092915050565b7f4d61782039207a6f6e6573000000000000000000000000000000000000000000600082015250565b60006129d3600b83611c6f565b91506129de8261299d565b602082019050919050565b60006020820190508181036000830152612a02816129c6565b9050919050565b7f54686520617070726f766564206164647265737320666f722074686973207a6f60008201527f6e6520616c726561647920657869737473000000000000000000000000000000602082015250565b6000612a65603183611c6f565b9150612a7082612a09565b604082019050919050565b60006020820190508181036000830152612a9481612a58565b9050919050565b7f5370656e64657220616464726573732069732065787465726e616c2e2055736560008201527f2063726f73732d636861696e207472616e736665722066756e6374696f6e2e00602082015250565b6000612af7603f83611c6f565b9150612b0282612a9b565b604082019050919050565b60006020820190508181036000830152612b2681612aea565b9050919050565b7f45524332303a20617070726f76652066726f6d20746865207a65726f2061646460008201527f7265737300000000000000000000000000000000000000000000000000000000602082015250565b6000612b89602483611c6f565b9150612b9482612b2d565b604082019050919050565b60006020820190508181036000830152612bb881612b7c565b9050919050565b7f45524332303a20617070726f766520746f20746865207a65726f20616464726560008201527f7373000000000000000000000000000000000000000000000000000000000000602082015250565b6000612c1b602283611c6f565b9150612c2682612bbf565b604082019050919050565b60006020820190508181036000830152612c4a81612c0e565b9050919050565b7f45524332303a206d696e7420746f20746865207a65726f206164647265737300600082015250565b6000612c87601f83611c6f565b9150612c9282612c51565b602082019050919050565b60006020820190508181036000830152612cb681612c7a565b9050919050565b7f45524332303a20696e73756666696369656e7420616c6c6f77616e6365000000600082015250565b6000612cf3601d83611c6f565b9150612cfe82612cbd565b602082019050919050565b60006020820190508181036000830152612d2281612ce6565b9050919050565b7f416464726573732069732065787465726e616c2e205573652063726f73732d6360008201527f6861696e207472616e736665722066756e6374696f6e2e000000000000000000602082015250565b6000612d85603783611c6f565b9150612d9082612d29565b604082019050919050565b60006020820190508181036000830152612db481612d78565b9050919050565b7f45524332303a207472616e736665722066726f6d20746865207a65726f20616460008201527f6472657373000000000000000000000000000000000000000000000000000000602082015250565b6000612e17602583611c6f565b9150612e2282612dbb565b604082019050919050565b60006020820190508181036000830152612e4681612e0a565b9050919050565b7f45524332303a207472616e7366657220746f20746865207a65726f206164647260008201527f6573730000000000000000000000000000000000000000000000000000000000602082015250565b6000612ea9602383611c6f565b9150612eb482612e4d565b604082019050919050565b60006020820190508181036000830152612ed881612e9c565b9050919050565b7f45524332303a207472616e7366657220616d6f756e742065786365656473206260008201527f616c616e63650000000000000000000000000000000000000000000000000000602082015250565b6000612f3b602683611c6f565b9150612f4682612edf565b604082019050919050565b60006020820190508181036000830152612f6a81612f2e565b9050919050565b7f45524332303a206275726e2066726f6d20746865207a65726f2061646472657360008201527f7300000000000000000000000000000000000000000000000000000000000000602082015250565b6000612fcd602183611c6f565b9150612fd882612f71565b604082019050919050565b60006020820190508181036000830152612ffc81612fc0565b9050919050565b7f45524332303a206275726e20616d6f756e7420657863656564732062616c616e60008201527f6365000000000000000000000000000000000000000000000000000000000000602082015250565b600061305f602283611c6f565b915061306a82613003565b604082019050919050565b6000602082019050818103600083015261308e81613052565b9050919050565b60006130a082611d7e565b91507fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff82036130d2576130d1612463565b5b600182019050919050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052601260045260246000fd5b600061311782611d7e565b915061312283611d7e565b925082613132576131316130dd565b5b828204905092915050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052604160045260246000fd5b600061317782611d7e565b915061318283611d7e565b925082820390508181111561319a57613199612463565b5b92915050565b60006131ab82611ea7565b91506131b683611ea7565b9250828201905060ff8111156131cf576131ce612463565b5b9291505056fea264697066735822122004d266eb4d8e6c7b46007ffb496065fbc55cd8941dfd992f51252bd983da633a64736f6c63430008130033"

var sha = "60806040523480156200001157600080fd5b5060405162001f7238038062001f72833981016040819052620000349162000325565b600f62000042848262000426565b50601062000051838262000426565b50601180546001600160a01b03191633908117909155819062000075908262000195565b505060408051808201825260008152601d60209182015260128054611d0061ffff199182161790915582518084018452601e8152603a90830152601380548216613a1e17905582518084018452603b815260579083015260148054821661573b17905582518084018452605881526073908301526015805482166173581790558251808401845260748152608f90830152601680548216618f74179055825180840184526090815260ab9083015260178054821661ab901790558251808401845260ac815260c79083015260188054821661c7ac1790558251808401845260c8815260e39083015260198054821661e3c8179055825180840190935260e4835260ff9290910191909152601a805490911661ffe4179055506200051a9050565b6001600160a01b038216620001f05760405162461bcd60e51b815260206004820152601f60248201527f45524332303a206d696e7420746f20746865207a65726f206164647265737300604482015260640160405180910390fd5b80600e6000828254620002049190620004f2565b90915550506001600160a01b038216600081815260208181526040808320805486019055518481527fddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef910160405180910390a35050565b505050565b634e487b7160e01b600052604160045260246000fd5b600082601f8301126200028857600080fd5b81516001600160401b0380821115620002a557620002a562000260565b604051601f8301601f19908116603f01168101908282118183101715620002d057620002d062000260565b81604052838152602092508683858801011115620002ed57600080fd5b600091505b83821015620003115785820183015181830184015290820190620002f2565b600093810190920192909252949350505050565b6000806000606084860312156200033b57600080fd5b83516001600160401b03808211156200035357600080fd5b620003618783880162000276565b945060208601519150808211156200037857600080fd5b50620003878682870162000276565b925050604084015190509250925092565b600181811c90821680620003ad57607f821691505b602082108103620003ce57634e487b7160e01b600052602260045260246000fd5b50919050565b601f8211156200025b57600081815260208120601f850160051c81016020861015620003fd5750805b601f850160051c820191505b818110156200041e5782815560010162000409565b505050505050565b81516001600160401b0381111562000442576200044262000260565b6200045a8162000453845462000398565b84620003d4565b602080601f831160018114620004925760008415620004795750858301515b600019600386901b1c1916600185901b1785556200041e565b600085815260208120601f198616915b82811015620004c357888601518255948401946001909101908401620004a2565b5085821015620004e25787850151600019600388901b60f8161c191681555b5050505050600190811b01905550565b808201808211156200051457634e487b7160e01b600052601160045260246000fd5b92915050565b611a48806200052a6000396000f3fe6080604052600436106101295760003560e01c8063593b79fe116100a5578063a457c2d711610074578063a9059cbb11610059578063a9059cbb14610375578063bc472aa314610395578063dd62ed3e146103cd57600080fd5b8063a457c2d714610335578063a534d9de1461035557600080fd5b8063593b79fe1461028657806370a08231146102d757806373cddab21461030d57806395d89b411461032057600080fd5b806323b872dd116100fc57806339509351116100e1578063395093511461020c578063399444bc1461022c578063429437bf1461024c57600080fd5b806323b872dd146101ca578063313ce567146101ea57600080fd5b806306fdde031461012e578063095ea7b31461015957806318160ddd1461018957806320e8dd93146101a8575b600080fd5b34801561013a57600080fd5b50610143610413565b60405161015091906115a8565b60405180910390f35b34801561016557600080fd5b506101796101743660046115de565b6104a5565b6040519015158152602001610150565b34801561019557600080fd5b50600e545b604051908152602001610150565b3480156101b457600080fd5b506101c86101c33660046115de565b6104bc565b005b3480156101d657600080fd5b506101796101e5366004611608565b61056d565b3480156101f657600080fd5b5060125b60405160ff9091168152602001610150565b34801561021857600080fd5b506101796102273660046115de565b61058f565b34801561023857600080fd5b506101fa610247366004611644565b6105ce565b34801561025857600080fd5b5061026c61026736600461165f565b6106e5565b6040805160ff938416815292909116602083015201610150565b34801561029257600080fd5b506101436102a1366004611644565b604051606082811b6bffffffffffffffffffffffff19166020830152906034016040516020818303038152906040529050919050565b3480156102e357600080fd5b5061019a6102f2366004611644565b6001600160a01b031660009081526020819052604090205490565b6101c861031b366004611678565b610708565b34801561032c57600080fd5b5061014361094c565b34801561034157600080fd5b506101796103503660046115de565b61095b565b34801561036157600080fd5b506101c8610370366004611706565b610a10565b34801561038157600080fd5b506101796103903660046115de565b610ce1565b3480156103a157600080fd5b506103b56103b036600461165f565b610cee565b6040516001600160a01b039091168152602001610150565b3480156103d957600080fd5b5061019a6103e8366004611772565b6001600160a01b03918216600090815260016020908152604080832093909416825291909152205490565b6060600f8054610422906117a5565b80601f016020809104026020016040519081016040528092919081815260200182805461044e906117a5565b801561049b5780601f106104705761010080835404028352916020019161049b565b820191906000526020600020905b81548152906001019060200180831161047e57829003601f168201915b5050505050905090565b60006104b2338484610d0e565b5060015b92915050565b3360026104c8826105ce565b60ff16600c81106104db576104db6117df565b01546040516bffffffffffffffffffffffff193360601b1660208201526001600160a01b03909116919091149060340160408051601f1981840301815290829052610528916020016117f5565b6040516020818303038152906040529061055e5760405162461bcd60e51b815260040161055591906115a8565b60405180910390fd5b506105698282610edc565b5050565b600061057a843384610f9b565b61058584848461102d565b5060019392505050565b3360008181526001602090815260408083206001600160a01b038716845290915281205490919061058590829086906105c9908790611877565b610d0e565b604080516bffffffffffffffffffffffff19606084901b1660208201528151601481830301815260349091019091526000908190600081518110610614576106146117df565b016020015160f81c905060005b60098160ff16101561069c5760128160ff16600d8110610643576106436117df565b015460ff9081169083161080159061067e575060128160ff16600d811061066c5761066c6117df565b015460ff610100909104811690831611155b1561068a579392505050565b806106948161188a565b915050610621565b5060405162461bcd60e51b815260206004820152601060248201527f496e76616c6964204c6f636174696f6e000000000000000000000000000000006044820152606401610555565b601281600d81106106f557600080fd5b015460ff80821692506101009091041682565b84f780156107585760405162461bcd60e51b815260206004820152601760248201527f41646472657373206973206e6f742065787465726e616c0000000000000000006044820152606401610555565b610762338661128f565b6000600261076f886105ce565b60ff16600c8110610782576107826117df565b01546001600160a01b03169050806108025760405162461bcd60e51b815260206004820152602f60248201527f546f6b656e206973206e6f7420617661696c61626c65206f6e2074686520646560448201527f7374696e6174696f6e20636861696e00000000000000000000000000000000006064820152608401610555565b60008561080f8686611877565b61081991906118a9565b905080341015610828826113f8565b60405160200161083891906118c0565b604051602081830303815290604052906108655760405162461bcd60e51b815260040161055591906115a8565b506040516001600160a01b03891660248201526044810188905260009060640160408051601f198184030181529190526020810180517bffffffffffffffffffffffffffffffffffffffffffffffffffffffff167f20e8dd930000000000000000000000000000000000000000000000000000000017815281519192506000918291829190898b8d858b81f69050896001600160a01b0316336001600160a01b03167fcf0ee562475620bbcd2f1b0675c8163317513271e4fdbbe9722436f247bd6d998b60405161093891815260200190565b60405180910390a350505050505050505050565b606060108054610422906117a5565b3360008181526001602090815260408083206001600160a01b0387168452909152812054909190838110156109f85760405162461bcd60e51b815260206004820152602560248201527f45524332303a2064656372656173656420616c6c6f77616e63652062656c6f7760448201527f207a65726f0000000000000000000000000000000000000000000000000000006064820152608401610555565b610a058286868403610d0e565b506001949350505050565b6011546001600160a01b03163314610a6a5760405162461bcd60e51b815260206004820152601660248201527f53656e646572206973206e6f74206465706c6f796572000000000000000000006044820152606401610555565b828114610adf5760405162461bcd60e51b815260206004820152603060248201527f636861696e20616e64206164647265737320617272617973206d75737420626560448201527f207468652073616d65206c656e677468000000000000000000000000000000006064820152608401610555565b60005b60ff8116841115610cda57600985858360ff16818110610b0457610b046117df565b9050602002016020810190610b199190611952565b60ff1610610b695760405162461bcd60e51b815260206004820152600b60248201527f4d61782039207a6f6e65730000000000000000000000000000000000000000006044820152606401610555565b60006002868660ff8516818110610b8257610b826117df565b9050602002016020810190610b979190611952565b60ff16600c8110610baa57610baa6117df565b01546001600160a01b031614610c285760405162461bcd60e51b815260206004820152603160248201527f54686520617070726f766564206164647265737320666f722074686973207a6f60448201527f6e6520616c7265616479206578697374730000000000000000000000000000006064820152608401610555565b82828260ff16818110610c3d57610c3d6117df565b9050602002016020810190610c529190611644565b600286868460ff16818110610c6957610c696117df565b9050602002016020810190610c7e9190611952565b60ff16600c8110610c9157610c916117df565b0180547fffffffffffffffffffffffff0000000000000000000000000000000000000000166001600160a01b039290921691909117905580610cd28161188a565b915050610ae2565b5050505050565b60006104b233848461102d565b600281600c8110610cfe57600080fd5b01546001600160a01b0316905081565b81f780610d835760405162461bcd60e51b815260206004820152603f60248201527f5370656e64657220616464726573732069732065787465726e616c2e2055736560448201527f2063726f73732d636861696e207472616e736665722066756e6374696f6e2e006064820152608401610555565b6001600160a01b038416610dfe5760405162461bcd60e51b8152602060048201526024808201527f45524332303a20617070726f76652066726f6d20746865207a65726f2061646460448201527f72657373000000000000000000000000000000000000000000000000000000006064820152608401610555565b6001600160a01b038316610e7a5760405162461bcd60e51b815260206004820152602260248201527f45524332303a20617070726f766520746f20746865207a65726f20616464726560448201527f73730000000000000000000000000000000000000000000000000000000000006064820152608401610555565b6001600160a01b0384811660008181526001602090815260408083209488168084529482529182902086905590518581527f8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b925910160405180910390a350505050565b6001600160a01b038216610f325760405162461bcd60e51b815260206004820152601f60248201527f45524332303a206d696e7420746f20746865207a65726f2061646472657373006044820152606401610555565b80600e6000828254610f449190611877565b90915550506001600160a01b038216600081815260208181526040808320805486019055518481527fddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef910160405180910390a35050565b6001600160a01b038381166000908152600160209081526040808320938616835292905220546000198114611027578181101561101a5760405162461bcd60e51b815260206004820152601d60248201527f45524332303a20696e73756666696369656e7420616c6c6f77616e63650000006044820152606401610555565b6110278484848403610d0e565b50505050565b81f7806110a25760405162461bcd60e51b815260206004820152603760248201527f416464726573732069732065787465726e616c2e205573652063726f73732d6360448201527f6861696e207472616e736665722066756e6374696f6e2e0000000000000000006064820152608401610555565b6001600160a01b03841661111e5760405162461bcd60e51b815260206004820152602560248201527f45524332303a207472616e736665722066726f6d20746865207a65726f20616460448201527f64726573730000000000000000000000000000000000000000000000000000006064820152608401610555565b6001600160a01b03831661119a5760405162461bcd60e51b815260206004820152602360248201527f45524332303a207472616e7366657220746f20746865207a65726f206164647260448201527f65737300000000000000000000000000000000000000000000000000000000006064820152608401610555565b6001600160a01b038416600090815260208190526040902054828110156112295760405162461bcd60e51b815260206004820152602660248201527f45524332303a207472616e7366657220616d6f756e742065786365656473206260448201527f616c616e636500000000000000000000000000000000000000000000000000006064820152608401610555565b6001600160a01b03858116600081815260208181526040808320888703905593881680835291849020805488019055925186815290927fddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef910160405180910390a3610cda565b6001600160a01b03821661130b5760405162461bcd60e51b815260206004820152602160248201527f45524332303a206275726e2066726f6d20746865207a65726f2061646472657360448201527f73000000000000000000000000000000000000000000000000000000000000006064820152608401610555565b6001600160a01b0382166000908152602081905260409020548181101561139a5760405162461bcd60e51b815260206004820152602260248201527f45524332303a206275726e20616d6f756e7420657863656564732062616c616e60448201527f63650000000000000000000000000000000000000000000000000000000000006064820152608401610555565b6001600160a01b0383166000818152602081815260408083208686039055600e80548790039055518581529192917fddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef910160405180910390a3505050565b60608160000361143b57505060408051808201909152600181527f3000000000000000000000000000000000000000000000000000000000000000602082015290565b8160005b8115611465578061144f81611975565b915061145e9050600a8361198e565b915061143f565b60008167ffffffffffffffff811115611480576114806119b0565b6040519080825280601f01601f1916602001820160405280156114aa576020820181803683370190505b509050815b851561154f576114c06001826119c6565b905060006114cf600a8861198e565b6114da90600a6118a9565b6114e490886119c6565b6114ef9060306119d9565b905060008160f81b90508084848151811061150c5761150c6117df565b60200101907effffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff1916908160001a905350611546600a8961198e565b975050506114af565b50949350505050565b60005b8381101561157357818101518382015260200161155b565b50506000910152565b60008151808452611594816020860160208601611558565b601f01601f19169290920160200192915050565b6020815260006115bb602083018461157c565b9392505050565b80356001600160a01b03811681146115d957600080fd5b919050565b600080604083850312156115f157600080fd5b6115fa836115c2565b946020939093013593505050565b60008060006060848603121561161d57600080fd5b611626846115c2565b9250611634602085016115c2565b9150604084013590509250925092565b60006020828403121561165657600080fd5b6115bb826115c2565b60006020828403121561167157600080fd5b5035919050565b600080600080600060a0868803121561169057600080fd5b611699866115c2565b97602087013597506040870135966060810135965060800135945092505050565b60008083601f8401126116cc57600080fd5b50813567ffffffffffffffff8111156116e457600080fd5b6020830191508360208260051b85010111156116ff57600080fd5b9250929050565b6000806000806040858703121561171c57600080fd5b843567ffffffffffffffff8082111561173457600080fd5b611740888389016116ba565b9096509450602087013591508082111561175957600080fd5b50611766878288016116ba565b95989497509550505050565b6000806040838503121561178557600080fd5b61178e836115c2565b915061179c602084016115c2565b90509250929050565b600181811c908216806117b957607f821691505b6020821081036117d957634e487b7160e01b600052602260045260246000fd5b50919050565b634e487b7160e01b600052603260045260246000fd5b7f53656e646572200000000000000000000000000000000000000000000000000081526000825161182d816007850160208701611558565b7f206e6f7420617070726f766564000000000000000000000000000000000000006007939091019283015250601401919050565b634e487b7160e01b600052601160045260246000fd5b808201808211156104b6576104b6611861565b600060ff821660ff81036118a0576118a0611861565b60010192915050565b80820281158282048414176104b6576104b6611861565b7f4e6f7420656e6f756768206761732073656e742c206e656564206174206c656181527f737420000000000000000000000000000000000000000000000000000000000060208201526000825161191e816023850160208701611558565b7f20776569000000000000000000000000000000000000000000000000000000006023939091019283015250602701919050565b60006020828403121561196457600080fd5b813560ff811681146115bb57600080fd5b60006001820161198757611987611861565b5060010190565b6000826119ab57634e487b7160e01b600052601260045260246000fd5b500490565b634e487b7160e01b600052604160045260246000fd5b818103818111156104b6576104b6611861565b60ff81811683821601908111156104b6576104b661186156fea26469706673582212204c6dd8a18c56cd6389a7fc7f0bf473d092abcc9aec3ae408859c35bbcc52713e64736f6c637822302e382e31392d646576656c6f702b636f6d6d69742e63383866343066642e6d6f640053000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000a00000000000000000000000000000000000000000000000000000000005f5e100000000000000000000000000000000000000000000000000000000000000000754657374696e6700000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000454495449000000000000000000000000000000000000000000000000000000004d90f003d3a429799d63fa92b4b7098f66fd98b05ab0a48f7147d7f313674627"

var testContract = "6080604052346200156457600062007a31803803809162000022826080620015a1565b608039610100811262001560576200003b6080620015c5565b60a0519092906001600160401b038111620015605762000063908360800190608001620015ff565b60c0519092906001600160401b03811162001432576200008b908260800190608001620015ff565b60e05192906001600160401b038411620015605760808301609f8501121562001560578360800151620000be816200165a565b94620000ce6040519687620015a1565b81865260208601906080860160a0600585901b83010111620010a25760a08101915b60a0600585901b83010183106200143657505061010051979150506001600160401b038711620014325760808401609f8801121562001432578660800151966200013a886200165a565b976200014a604051998a620015a1565b80895260208901916080870160a0600584901b83010111620011b85760a08101925b60a0600584901b83010184106200136257505061012051979150506001600160401b0387116200135e5760808501609f880112156200135e578660800151620001b5816200165a565b97620001c5604051998a620015a1565b81895260208901906080880160a0600585901b830101116200135a5760a08101915b60a0600585901b83010183106200122457505061014051949150506001600160401b038411620010a25760808601609f85011215620010a25783608001519362000231856200165a565b94620002416040519687620015a1565b80865260208601916080890160a0600784901b83010111620012205760a08101925b60a0600784901b8301018410620011bc575050610160519150506001600160401b038111620011b85760808701609f82011215620011b8578060800151620002ab816200165a565b97620002bb604051998a620015a1565b81895260208901926080820160a0600685901b83010111620011b45760a08101935b60a0600685901b83010185106200116a57505084519250506001600160401b0382119050620008cc576200031360025462001680565b601f811162001129575b50806020601f8211600114620010b2578791620010a6575b508160011b916000199060031b1c1916176002555b6daaeb6d7670e522a718067333cd4e3b62000ff8575b6200036d60075462001680565b601f811162000fb6575b50600a640302e372e360dc1b016007556005600b55600019600c558051906001600160401b03821162000e18578190620003b360085462001680565b601f811162000f74575b50602090601f831160011462000ef65760009262000eea575b50508160011b916000199060031b1c1916176008555b6001600160a01b0382166000908152600080516020620079b1833981519152602052604090205460ff161562000e8c575b6000805160206200799183398151915260005260066020526200046a6001600160a01b0383167fcba48364d7bf479cad53f4f02b8ea61ab254f90435c40375f1022e1f8bd53d7362001868565b506001600160a01b038216600090815260008051602062007951833981519152602052604090205460ff161562000e2e575b600080516020620079d18339815191526000526006602052620004e96001600160a01b0383167f6f33ec38532bdfedd8912126adc1f5918b75385d650da7c642efcc94ef3a60f562001868565b508051906001600160401b03821162000e185781906200050b60095462001680565b601f811162000dca575b50602090601f831160011462000d4c5760009262000d40575b50508160011b916000199060031b1c1916176009555b600160ff19600a541617600a5562000589604051620005638162001569565b60018082526001600160a01b0384166020830152604082018190526060820152620017de565b6001600160a01b0381161562000cfb576103e86020604051620005ac8162001585565b6001600160a01b0393909316808452920152607d60a31b17600355600080516020620079918339815191528252600560209081526040808420336000908152925290205460ff16801562000cc3575b6200060690620018f5565b6000805160206200799183398151915282526005602052604082203360005260205260ff60406000205416801562000c8b575b6200064490620018f5565b815b84518110156200070c57806200066d6200066562000706938862001958565b51516200196d565b62000679828862001958565b516200068a815160018401620016d6565b6200069d602082015160028401620016d6565b604081015160038301556004820190620006c960608201511515839060ff801983541691151516179055565b608081015115159061ff0062ff000060a08554930151151560101b169260081b169062ffff00191617179055600160ff1982541617905562001932565b62000646565b50859350846000805160206200799183398151915283526005602052604083203360005260205260ff60406000205416801562000c53575b6200074f90620018f5565b825b85518110156200095e576200076b62000665828862001958565b9060406200077a828962001958565b510151916001600160a01b03606062000794848b62001958565b510151169060ff81541615620009195760016020620007b4858c62001958565b510151620007f8620007e2600760405195620007d08762001585565b85875260208701948552018862001995565b93511515849060ff801983541691151516179055565b5191015580151580620008e0575b6200081f575b5062000819915062001932565b62000751565b6040516020818551620008368183858a01620015da565b60109082019081520301902080546001600160a01b031916909117905560115468010000000000000000811015620008cc576001810180601155811015620008b65760116000526200081992620008af917f31ecc21a745e3968a04e9570e4425bc18fa8019c68028196b546d1669c200c6801620016d6565b876200080c565b634e487b7160e01b600052603260045260246000fd5b634e487b7160e01b86526041600452602486fd5b50806040518451620008f7818360208901620015da565b60109082019081528190036020019020546001600160a01b0316141562000806565b60405162461bcd60e51b815260206004820152601860248201527f546f6b656e206b6579206e6f74207265676973746572656400000000000000006044820152606490fd5b50836000805160206200799183398151915284526005602052604084203360005260205260ff60406000205416801562000c1b575b620009a3909493929194620018f5565b82935b815185101562000ac657620009e66006620009d16020620009c8898762001958565b5101516200196d565b01620009de878562001958565b515162001995565b94620009f3818462001958565b519562000a05875160018301620016d6565b62000a18602088015160028301620016d6565b60408701516003820155606087015196600497888301556080810151600583015560a0810151600281101562000ab35760068301805460ff90921660ff1992831617905560c0820151600784015560e0909101516008830180546001600160a01b0319166001600160a01b03929092169190911790558154166001179055939450919290919062000aa99062001932565b93929190620009a6565b634e487b7160e01b885260218952602488fd5b8362000ad284620019bd565b6000805160206200799183398151915281526005602052604081203360005260205260ff60406000205416801562000be3575b62000b1090620018f5565b815181101562000bd3578062000b84602062000b3162000b8b948662001958565b5101516001600160a01b0362000b48848762001958565b5151169080600052600560205260406000208260005260205260ff604060002054161562000b91575b6000526006602052604060002062001868565b5062001932565b62000b10565b8060005260056020526040600020826000526020526040600020600160ff1982541617905533828260008051602062007931833981519152600080a462000b71565b604051615d3b908162001bf68239f35b50600080516020620079d183398151915281526005602052604081203360005260205262000b1060ff60406000205416905062000b05565b50600080516020620079d1833981519152845260056020526040842033600052602052620009a360ff60406000205416905062000993565b50600080516020620079d18339815191528352600560205260408320336000526020526200074f60ff60406000205416905062000744565b50600080516020620079d18339815191528252600560205260408220336000526020526200064460ff60406000205416905062000639565b50600080516020620079d18339815191528252600560205260408220336000526020526200060660ff604060002054169050620005fb565b60405162461bcd60e51b815260206004820152601960248201527f455243323938313a20696e76616c6964207265636569766572000000000000006044820152606490fd5b0151905038806200052e565b60096000908152935060008051602062007a1183398151915291905b601f198416851062000dae576001945083601f1981161062000d94575b505050811b0160095562000544565b015160001960f88460031b161c1916905538808062000d85565b8181015183556020948501946001909301929091019062000d68565b600960005262000e069060008051602062007a11833981519152601f850160051c8101916020861062000e0d575b601f0160051c0190620016bd565b3862000515565b909150819062000df8565b634e487b7160e01b600052604160045260246000fd5b6001600160a01b03821660008181526000805160206200795183398151915260205260408120805460ff19166001179055339190600080516020620079d183398151915290600080516020620079318339815191529080a46200049c565b6001600160a01b0382166000818152600080516020620079b183398151915260205260408120805460ff191660011790553391906000805160206200799183398151915290600080516020620079318339815191529080a46200041d565b015190503880620003d6565b600860009081529350600080516020620079f183398151915291905b601f198416851062000f58576001945083601f1981161062000f3e575b505050811b01600855620003ec565b015160001960f88460031b161c1916905538808062000f2f565b8181015183556020948501946001909301929091019062000f12565b600860005262000faf90600080516020620079f1833981519152601f850160051c8101916020861062000e0d57601f0160051c0190620016bd565b38620003bd565b600760005262000ff190601f0160051c7fa66cc928b5edb82af9bd49922954155ab7b0942694bea4ce44661d9a8736c68890810190620016bd565b3862000377565b6daaeb6d7670e522a718067333cd4e3b15620010a257604051633e9f1edf60e11b8152306004820152733cc6cdda760b79bafa08df41ecfa224f810dceb660248201528581604481836daaeb6d7670e522a718067333cd4e5af18015620010975762001066575b5062000360565b9094906001600160401b038111620010835760405293386200105f565b634e487b7160e01b82526041600452602482fd5b6040513d88823e3d90fd5b8480fd5b90508301513862000335565b6002885287925060008051602062007971833981519152905b601f198316841062001110576001935082601f19811610620010f6575b5050811b016002556200034a565b85015160001960f88460031b161c191690553880620010e8565b85810151825560209384019360019092019101620010cb565b60028752620011639060008051602062007971833981519152601f840160051c8101916020851062000e0d57601f0160051c0190620016bd565b386200031d565b604085846080010312620011b0579060406020809382516200118c8162001585565b6200119789620015c5565b81528289015183820152815201950194909150620002dd565b8980fd5b8880fd5b8580fd5b6080848b6080010312620011b45790608060208093604051620011df8162001569565b620011ea8862001672565b8152620011f9838901620015c5565b83820152604088015160408201526060880151606082015281520194019390915062000263565b8780fd5b82516001600160401b038111620011b4576101008382018b03601f190112620011b457604051906001600160401b036101008301908111908311176200134657610100820160405260a084820101516001600160401b03811162001342576200129c9060208d608001918488608001010101620015ff565b825260c084820101516001600160401b0381116200134257620012ce9060208d608001918488608001010101620015ff565b602083015280840160e081015160408401526101008101516060840152610120810151608084015261014001516002811015620013425760a0830152830161016081015160c08301526020928392839260e090620013309061018001620015c5565b908201528152019301929050620001e7565b8a80fd5b634e487b7160e01b8a52604160045260248afd5b8680fd5b8380fd5b83516001600160401b038111620012205760808382018a03601f190112620012205760405190620013938262001569565b60a084820101516001600160401b038111620011b057620013c39060208c608001918488608001010101620015ff565b825280840160c0810151602084015260e001516001600160401b038111620011b05792602093926200141f60808695946200140e8f9688809860800191848d608001010101620015ff565b6040850152886080010101620015c5565b606082015281520194019390506200016c565b8280fd5b82516001600160401b0381116200135a5760c08382018903601f1901126200135a57604051906001600160401b0360c08301908111908311176200154c5760c0820160405260a084820101516001600160401b038111620011b457620014ab9060208b608001918488608001010101620015ff565b825260c084820101516001600160401b038111620011b4579260209392849392620014e58594858e60800191848b608001010101620015ff565b8483015280870160e081015160408401526080916200153a9160c0919062001511906101000162001672565b606086015260a0936200152a6101208c84010162001672565b9086015289608001010162001672565b908201528152019301929050620000f0565b634e487b7160e01b88526041600452602488fd5b5080fd5b600080fd5b608081019081106001600160401b0382111762000e1857604052565b604081019081106001600160401b0382111762000e1857604052565b601f909101601f19168101906001600160401b0382119082101762000e1857604052565b51906001600160a01b03821682036200156457565b60005b838110620015ee5750506000910152565b8181015183820152602001620015dd565b81601f82011215620015645780516001600160401b03811162000e18576040519262001636601f8301601f191660200185620015a1565b818452602082840101116200156457620016579160208085019101620015da565b90565b6001600160401b03811162000e185760051b60200190565b519081151582036200156457565b90600182811c92168015620016b2575b60208310146200169c57565b634e487b7160e01b600052602260045260246000fd5b91607f169162001690565b818110620016c9575050565b60008155600101620016bd565b81519192916001600160401b03811162000e1857620016f6825462001680565b601f8111620017a8575b50602080601f83116001146200174057508192939460009262001734575b50508160011b916000199060031b1c1916179055565b0151905038806200171e565b90601f198316958460005282600020926000905b8882106200178f5750508360019596971062001775575b505050811b019055565b015160001960f88460031b161c191690553880806200176b565b8060018596829496860151815501950193019062001754565b620017d790836000526020600020601f840160051c8101916020851062000e0d57601f0160051c0190620016bd565b3862001700565b600f546801000000000000000081101562000e18576001810180600f55811015620008b6576060600291600f60005260036020600020910201926200183281511515859060ff801983541691151516179055565b60208101518454610100600160a81b03191660089190911b610100600160a81b0316178455604081015160018501550151910155565b91906001830160009082825280602052604082205415600014620018ef5784549468010000000000000000861015620018db5760018601808255861015620018c757836040949596828552602085200155549382526020522055600190565b634e487b7160e01b83526032600452602483fd5b634e487b7160e01b83526041600452602483fd5b50925050565b15620018fd57565b60405162461bcd60e51b815260206004820152600d60248201526c1058d8d95cdcc811195b9a5959609a1b6044820152606490fd5b6000198114620019425760010190565b634e487b7160e01b600052601160045260246000fd5b8051821015620008b65760209160051b010190565b602062001988918160405193828580945193849201620015da565b8101600e81520301902090565b602090620019b1928260405194838680955193849201620015da565b82019081520301902090565b336000908152600080516020620079b1833981519152602090815260408083205491939092909160ff16801562001bc9575b620019fa90620018f5565b6001918281511062001bc257600f5482600f558062001b7f575b5080511562001b6b57606091838387840151015193829383925b62001aa1575b505050821562001a8d5750040362001a4a575050565b60649250519062461bcd60e51b82526004820152601a60248201527f53706c697473206d7573742061646420757020746f20313030250000000000006044820152fd5b634e487b7160e01b81526012600452602490fd5b909193815185101562001b64578762001abb868462001958565b510151810180911162001b50579362001ae062001ad9828462001958565b51620017de565b858362001aee838562001958565b5101510362001b0c579062001b0587939262001932565b9262001a2e565b875162461bcd60e51b8152600481018a9052601a60248201527f53706c697473206d75737420686176652073616d6520626173650000000000006044820152606490fd5b634e487b7160e01b84526011600452602484fd5b9362001a34565b634e487b7160e01b82526032600452602482fd5b600390808202908282040362001b5057600f8452868420908101905b81811062001bab57505062001a14565b808584925585878201558560028201550162001b9b565b5050505050565b50600080516020620079d183398151915281526005845282812033825284528281205460ff16620019ef56fe6080604052600436101561001257600080fd5b60003560e01c8062fdd58e146132e457806301ffc9a71461322857806302fb0c5e1461320557806302fe53051461306657806304634d8d14612f0557806306577f2614612e8b57806306fdde0314612de65780630e89341c14612ab4578063248a9ca314612a8557806327ea6f2b14612a1657806328995aca146129ae5780632a55205a1461290a5780632eb2c2d6146125d75780632f2ff15d1461259857806336568abe146125065780633888cefb146119ba57806341f434341461199157806344cfa5a41461189357806344e95e22146117cf57806346694b7d14611798578063473157c2146117375780634e1273f4146115f9578063520db9061461157857806354fd4d50146114aa5780635f145a261461143b578063670b04dd146110185780636853920e14610f9e57806375c303c914610f8057806380f3d77014610f4857806386770e4314610f105780638acb99ac14610ed95780639010d07c14610e9257806391d1485414610e4557806398bdf6f514610e27578063997e351a14610def578063a0617ad014610dd1578063a217fddf14610db5578063a22cb46514610cd7578063acec338a14610c50578063be7edebe14610a9b578063c09e60bd14610a4f578063c18cfe8614610907578063c195b856146108cf578063ca15c873146108a3578063ce1d1b7a146107c9578063d547741f1461078a578063e58378bb14610761578063e68f3bd8146106c1578063e6c3b1f61461067a578063e985e9c514610624578063ec87621c146105fb578063f069f5cf146105c3578063f242432a1461031a578063fd338353146102e05763fddd53d71461027857600080fd5b346102db5760203660031901126102db576004356001600160401b0381116102db5760ff60046102c460206102b181953690850161340b565b8160405193828580945193849201613532565b8101600e8152030190200154166040519015158152f35b600080fd5b346102db5760203660031901126102db576004356001600160401b0381116102db5761031361031891369060040161387e565b615479565b005b346102db5760a03660031901126102db5761033361330b565b61033b613321565b906064356044356084356001600160401b0381116102db5761036190369060040161340b565b6001600160a01b0393841693338514801561059a575b610380906140ba565b851661038d81151561411d565b61039683614401565b506103a084614401565b5082600052602095600087526040600020866000528752846040600020546103ca82821015614177565b85600052600089526040600020886000528952036040600020558360005260008752604060002082600052875260406000206104078682546141e4565b90558186604051868152878a820152600080516020615c6683398151915260403392a43b61043157005b61047593600087946040519687958694859363f23a6e6160e01b9b8c865233600487015260248601526044850152606484015260a0608484015260a4830190613555565b03925af16000918161056b575b5061054157505060019061049461425a565b6308c379a01461050c575b506104a657005b60405162461bcd60e51b815260206004820152603460248201527f455243313135353a207472616e7366657220746f206e6f6e2d455243313135356044820152732932b1b2b4bb32b91034b6b83632b6b2b73a32b960611b6064820152608490fd5b0390fd5b610514614278565b9081610520575061049f565b61050860405192839262461bcd60e51b845260048401526024830190613555565b6001600160e01b0319161490506103185760405162461bcd60e51b81528061050860048201614211565b61058c919250843d8611610593575b61058481836133cd565b8101906141f1565b9084610482565b503d61057a565b5084600052600160205260406000203360005260205261038060ff604060002054169050610377565b346102db5760203660031901126102db576004356001600160401b0381116102db576105f6610318913690600401613798565b61509f565b346102db5760003660031901126102db576020604051600080516020615cc68339815191528152f35b346102db5760403660031901126102db5761063d61330b565b610645613321565b9060018060a01b03809116600052600160205260406000209116600052602052602060ff604060002054166040519015158152f35b346102db5760203660031901126102db57600435600052600d6020526106bd6106a9600160406000200161348c565b604051918291602083526020830190613555565b0390f35b346102db5760403660031901126102db576106da613656565b336000908152600080516020615ca6833981519152602052604090205460ff16801561073b575b61070a9061461b565b6004356000908152600d60205260409020600201805460ff60a01b191691151560a01b60ff60a01b16919091179055005b50336000908152600080516020615c46833981519152602052604090205460ff16610701565b346102db5760003660031901126102db576020604051600080516020615c868339815191528152f35b346102db5760403660031901126102db576103186004356107a9613321565b908060005260056020526107c4600160406000200154613c1d565b613f7f565b346102db576020806003193601126102db576004356001600160401b0381116102db576107fa90369060040161340b565b90600080516020615c8683398151915260005260058152604060002033600052815260ff604060002054168015610873575b15610843576103188261083d61568d565b906159b8565b6064906040519062461bcd60e51b8252600482015260096024820152684e6f2061636365737360b81b6044820152fd5b50600080516020615cc683398151915260005260058152604060002033600052815260ff6040600020541661082c565b346102db5760203660031901126102db5760043560005260066020526020604060002054604051908152f35b346102db5760203660031901126102db576004356001600160401b0381116102db57610902610318913690600401613672565b614f94565b346102db576020806003193601126102db5761092161330b565b90600080516020615c8683398151915260005260058152604060002033600052815261095460ff6040600020541661461b565b6040519061096182613361565b6001928383528160005b818110610a1d575050604051906109818261337c565b8482526001600160a01b03168282015260408101849052606081018490526109a883614099565b526109b282614099565b506000835b6109e4575b6103188383656e617469766560d01b604051916109d883613361565b600683528201526159b8565b601154811015610a185780610a0d84610a08610a02610a1295614466565b5061348c565b6159b8565b61408a565b836109b7565b6109bc565b604051610a298161337c565b60008152600083820152600060408201526000606082015282828701015201829061096b565b346102db5760203660031901126102db576004356001600160401b0381116102db576003610a8760206102b18194369060040161340b565b8101600e8152030190200154604051908152f35b346102db576020806003193601126102db576001600160401b036004358181116102db57610acd90369060040161340b565b91600080516020615c8683398151915260005260058152604060002033600052815260ff604060002054168015610c22575b610b089061461b565b8251918211610c0c57610b1c600954613452565b601f8111610bc5575b5080601f8311600114610b6157508192600092610b56575b5050600019600383901b1c191660019190911b17600955005b015190508280610b3d565b90601f19831693600960005282600020926000905b868210610bad5750508360019510610b94575b505050811b01600955005b015160001960f88460031b161c19169055828080610b89565b80600185968294968601518155019501930190610b76565b600960005281600020601f840160051c810191838510610c02575b601f0160051c01905b818110610bf65750610b25565b60008155600101610be9565b9091508190610be0565b634e487b7160e01b600052604160045260246000fd5b50600080516020615cc68339815191526000908152600582526040808220338352835290205460ff16610aff565b346102db5760203660031901126102db576004358015158091036102db57336000908152600080516020615ca6833981519152602052604090205460ff168015610cb1575b610c9e9061461b565b60ff8019600a5416911617600a55600080f35b50336000908152600080516020615c46833981519152602052604090205460ff16610c95565b346102db5760403660031901126102db57610cf061330b565b610cf8613656565b6001600160a01b0390911690338214610d5e57336000526001602052604060002082600052602052610d2e816040600020613f6e565b60405190151581527f17307eab39ab6107e8899845ad3d59bd9653f200f220920489ca2b5937696c3160203392a3005b60405162461bcd60e51b815260206004820152602960248201527f455243313135353a2073657474696e6720617070726f76616c20737461747573604482015268103337b91039b2b63360b91b6064820152608490fd5b346102db5760003660031901126102db57602060405160008152f35b346102db5760003660031901126102db576020600c54604051908152f35b346102db5760203660031901126102db576004356001600160401b0381116102db576005610a8760206102b18194369060040161340b565b346102db5760003660031901126102db576020601254604051908152f35b346102db5760403660031901126102db57610e5e613321565b600435600052600560205260406000209060018060a01b0316600052602052602060ff604060002054166040519015158152f35b346102db5760403660031901126102db5760043560005260066020526020610ec06024356040600020614481565b905460405160039290921b1c6001600160a01b03168152f35b346102db5760203660031901126102db57600435600052600d602052602060018060a01b0360026040600020015416604051908152f35b346102db5760203660031901126102db576004356001600160401b0381116102db57610f436103189136906004016139a1565b615736565b346102db5760203660031901126102db576004356001600160401b0381116102db57610f7b610318913690600401613a45565b6155e6565b346102db5760003660031901126102db576020600b54604051908152f35b346102db5760403660031901126102db57610318610fba61330b565b336000908152600080516020615ca6833981519152602052604090205460ff168015610ff2575b610fea9061461b565b602435613f7f565b50336000908152600080516020615c46833981519152602052604090205460ff16610fe1565b6101003660031901126102db576004356001600160401b0381116102db57611044903690600401613b9d565b6024356001600160401b0381116102db576110639036906004016135f8565b906044356001600160401b0381116102db57611083903690600401613b03565b916064356001600160401b0381116102db576110a3903690600401613b9d565b6084356001600160401b0381116102db576110c2903690600401613b03565b60a4356001600160401b0381116102db576110e1903690600401613b9d565b6001600160401b0360c435116102db5736602360c4350112156102db5760c435600401359061110f826135e1565b9161111d60405193846133cd565b80835260208301903660248260051b60c4350101116102db57602460c43501915b60248260051b60c435010183106114065750506001600160401b0360e4351190506102db5736602360e4350112156102db5761117f60e435600401356135e1565b9661118d60405198896133cd565b60e4356004013588526020880136602460e4356004013560051b60e4350101116102db57602460e43501905b602460e4356004013560051b60e435010182106113d65750506111e060ff600a5416614766565b86518651811490816113cb575b816113c0575b816113b5575b816113aa575b8161139f575b81611394575b50156113595760009560005b88518110156112de578087818080808f8f908c8c8f8d908d61123a8880986140a6565b519c611245916140a6565b519a6001600160a01b0392839061125d9089906140a6565b511696611269916140a6565b5196611274916140a6565b511695611280916140a6565b519561128b916140a6565b5195611296916140a6565b51956112a197614849565b6112ab82896140a6565b516112b59061479f565b6112c9575b506112c49061408a565b611217565b6112d7906112c492996141e4565b97906112ba565b336000908152600080516020615ca6833981519152602052604090205460ff1688811561134e575b501561130e57005b60405162461bcd60e51b815260206004820152601860248201527709cdee840cadcdeeaced040c4c2d840ccdee440c4c2e8c6d60431b6044820152606490fd5b905034101581611306565b60405162461bcd60e51b8152602060048201526013602482015272082e4ce40d8cadccee8d040dad2e6dac2e8c6d606b1b6044820152606490fd5b90508851148961120b565b845181149150611205565b8351811491506111ff565b8551811491506111f9565b8651811491506111f3565b8251811491506111ed565b6001600160401b038235116102db57602080916113fb366024863560e435010161340b565b8152019101906111b9565b8235906001600160401b0382116102db576020809161142e60249485369160c43501016135f8565b815201930192905061113e565b346102db5760203660031901126102db57336000908152600080516020615ca6833981519152602052604090205460ff168015611484575b61147c9061461b565b600435600c55005b50336000908152600080516020615c46833981519152602052604090205460ff16611473565b346102db5760003660031901126102db576040516000906007546114cd81613452565b80835260019180831690811561155057506001146114f6575b6106bd836106a9818703826133cd565b6007600090815260209450917fa66cc928b5edb82af9bd49922954155ab7b0942694bea4ce44661d9a8736c6885b82841061153d575050508101909101906106a9816114e6565b8054858501870152928501928101611524565b6106bd95506106a993506020915091849260ff191682840152151560051b82010193506114e6565b346102db5760003660031901126102db5761159161568d565b6040516020918282018383528151809152836040840192019360005b8281106115ba5784840385f35b8551805115158552808301516001600160a01b0316858401526040808201519086015260609081015190850152948101946080909301926001016115ad565b346102db5760403660031901126102db576001600160401b036004358181116102db5761162a903690600401613b03565b906024359081116102db576116439036906004016135f8565b9080518251036116e057805191611659836135e1565b9261166760405194856133cd565b808452611676601f19916135e1565b0136602085013760005b82518110156116ca576116c5906116b56001600160a01b036116a283876140a6565b51166116ae83866140a6565b5190614005565b6116bf82876140a6565b5261408a565b611680565b604051602080825281906106bd90820187613b69565b60405162461bcd60e51b815260206004820152602960248201527f455243313135353a206163636f756e747320616e6420696473206c656e677468604482015268040dad2e6dac2e8c6d60bb1b6064820152608490fd5b346102db5760203660031901126102db57600435600f548110156102db57611760608091613ace565b5080549060026001820154910154906040519260ff81161515845260018060a01b039060081c16602084015260408301526060820152f35b346102db5760203660031901126102db57600435600052600d602052602060ff60026040600020015460a01c166040519015158152f35b6101003660031901126102db576001600160401b036004358181116102db576117fc90369060040161340b565b90611805613337565b916064358281116102db5761181e90369060040161340b565b6084356001600160a01b03811681036102db5760a4358481116102db5761184990369060040161340b565b9060c4358581116102db576118629036906004016135f8565b9260e4359586116102db5760209661188161188b97369060040161340b565b9560243590614849565b604051908152f35b346102db5760a03660031901126102db576001600160401b036004358181116102db576118c4903690600401613672565b6024358281116102db576118dc903690600401613798565b916044358181116102db576118f590369060040161387e565b926064358281116102db5761190e9036906004016139a1565b906084359283116102db5761031894610313610f43926105f6611938610f7b973690600401613a45565b336000908152600080516020615ca6833981519152602052604090205490989060ff16801561196b575b6109029061461b565b50336000908152600080516020615c46833981519152602052604090205460ff16611962565b346102db5760003660031901126102db5760206040516daaeb6d7670e522a718067333cd4e8152f35b60803660031901126102db576001600160401b036004358181116102db576119e690369060040161340b565b6119ee613337565b916064359081116102db57611a0790369060040161340b565b604051611a13816133b2565b6000815260405190611a24826133b2565b60008252604051611a34816133b2565b60008152611a4660ff600a5416614766565b60036040516020818851611a5d8183858d01613532565b8101600e8152030190200154600081129081156124cb575b501561248a57600c5460008112908115612472575b501561243357600b5460243510156123fe5760ff600460405160208181611ab78b83815193849201613532565b8101600e815203019020015416156123be57611ad28461479f565b8015612389575b1561234e5760ff611b0d600760405160208181611afc8c83815193849201613532565b8101600e81520301902001866135a0565b54161561231357611b7d611b33600760405160208181611afc8c83815193849201613532565b93600160405195611b4387613361565b60ff8154161515875201546020860152600660405160208181611b6c8c83815193849201613532565b8101600e81520301902001906135a0565b9160ff600460405160208181611b998c83815193849201613532565b8101600e815203019020015460101c1680612307575b806122e0575b6122a55760ff835416611f26575b505050611bcf8261479f565b15611d9d57336000908152600080516020615ca68339815191526020526040902054611c07925060ff16908115611d82575b506147f4565b6012549060018201808311611d6c5760125560056040516020818451611c308183858901613532565b8101600e8152030190200190815460018101809111611d6c57611c7c925582600052600d602052611c68816001604060002001614657565b602060405192828480945193849201613532565b810103902081600080516020615ce6833981519152600080a360405190611ca2826133b2565b600082526001600160a01b038316928315611d1d5761031893611cc483614401565b50611ccd6143db565b508260005260006020526040600020816000526020526040600020611cf281546141d6565b9055600060405184815260016020820152600080516020615c6683398151915260403392a4336142e9565b60405162461bcd60e51b815260206004820152602160248201527f455243313135353a206d696e7420746f20746865207a65726f206164647265736044820152607360f81b6064820152608490fd5b634e487b7160e01b600052601160045260246000fd5b611d9491506020602435910151614422565b34101584611c01565b336000908152600080516020615ca6833981519152602052604090205460ff1615611dca575b5050611c07565b602460206040518451611de08183858901613532565b601090820190815281900382019020546040516370a0823160e01b815233600482015292839182906001600160a01b03165afa908115611ee557600091611ef1575b50906064611e80600094611e48602095611e4160243588880151614422565b11156147f4565b84611e5c6040519283815193849201613532565b81019060108252858160018060a01b03930301902054169284602435910151614422565b60405194859384926323b872dd60e01b845233600485015230602485015260448401525af18015611ee557611eb6575b80611dc3565b611ed79060203d602011611ede575b611ecf81836133cd565b810190614831565b5082611eb0565b503d611ec5565b6040513d6000823e3d90fd5b9190506020823d602011611f1e575b81611f0d602093836133cd565b810103126102db5790516064611e22565b3d9150611f00565b60ff600684015416600281101561228f576001810361217057505060018060a01b03611fbf611fb782600886015416936040516020810190858c16825260208152611f7081613361565b51902060405160208101917b0ca2ba3432b932bab69029b4b3b732b21026b2b9b9b0b3b29d05199960211b8352603c820152603c8152611faf81613397565b5190206153bc565b9190916152bd565b160361212d575b611fe66020830151612710611fdf600385015483614422565b049061451e565b6020830152600581015460048201549060008112908115612113575b50156120d557600081129081156120a7575b501561206357600981015490600182018211611d6c576001600a9201600982015560018060a01b0386166000520160205260406000208054600181018111611d6c576001019055848080611bc3565b60405162461bcd60e51b815260206004820152601c60248201527b4d61782075736573207265616368656420666f72206164647265737360201b6044820152606490fd5b905060018060a01b038616600052600a82016020526120cd6024356040600020546141e4565b111586612014565b60405162461bcd60e51b815260206004820152601660248201527513585e081d5cd95cc81d1bdd185b081c995858da195960521b6044820152606490fd5b905061212560243560098501546141e4565b111587612002565b60405162461bcd60e51b815260206004820152601b60248201527a139bdd081bdb881cda59db985d1d5c9948185b1b1bddc81b1a5cdd602a1b6044820152606490fd5b90949150959294919515600014612252576007860154604051606085901b6001600160601b0319166020820190815260148252919691906121b081613361565b519020966000975b8651891015612204576121cb89886140a6565b5190818110156121f0576000526020526121ea60406000205b9861408a565b976121b8565b906000526020526121ea60406000206121e4565b94975092959194509214611fc65760405162461bcd60e51b8152602060048201526018602482015277139bdd081bdb881b595c9adb1948185b1b1bddc81b1a5cdd60421b6044820152606490fd5b60405162461bcd60e51b8152602060048201526015602482015274496e76616c696420646973636f756e74207479706560581b6044820152606490fd5b634e487b7160e01b600052602160045260246000fd5b60405162461bcd60e51b8152602060048201526013602482015272151bdad95b881d1e5c19481a5cc819d85d1959606a1b6044820152606490fd5b50336000908152600080516020615ca6833981519152602052604090205460ff1615611bb5565b5060ff83541615611baf565b60405162461bcd60e51b8152602060048201526013602482015272151e5c19481b9bdd081c9959da5cdd195c9959606a1b6044820152606490fd5b60405162461bcd60e51b815260206004820152601360248201527210dd5c9c881b9bdd081c9959da5cdd195c9959606a1b6044820152606490fd5b50604051845161239d818360208901613532565b60109082019081528190036020019020546001600160a01b03161515611ad9565b60405162461bcd60e51b8152602060048201526018602482015277546f6b656e2074797065206973206e6f742061637469766560401b6044820152606490fd5b60405162461bcd60e51b815260206004820152600d60248201526c115e18d959591cc81b1a5b5a5d609a1b6044820152606490fd5b60405162461bcd60e51b815260206004820152601760248201527613585e081cdd5c1c1b1e48199bdc8818dbdb9d1c9858dd604a1b6044820152606490fd5b90506124826024356012546141e4565b111587611a8a565b60405162461bcd60e51b81526020600482015260196024820152784d617820737570706c7920666f7220746f6b656e207479706560381b6044820152606490fd5b90506124fe604051600588516124e5818460208d01613532565b820191600e8352602081602435940301902001546141e4565b111587611a75565b346102db5760403660031901126102db5761251f613321565b336001600160a01b0382160361253b5761031890600435613f7f565b60405162461bcd60e51b815260206004820152602f60248201527f416363657373436f6e74726f6c3a2063616e206f6e6c792072656e6f756e636560448201526e103937b632b9903337b91039b2b63360891b6064820152608490fd5b346102db5760403660031901126102db576103186004356125b7613321565b908060005260056020526125d2600160406000200154613c1d565b613ee1565b346102db5760031960a0368201126102db576125f161330b565b906125fa613321565b906001600160401b03906044358281116102db5761261c9036906004016135f8565b6064358381116102db576126349036906004016135f8565b926084359081116102db5761264d90369060040161340b565b6001600160a01b039586169590929033871480156128e1575b61266f906140ba565b825185510361288b5785169261268684151561411d565b60005b835181101561271f57806126a061271a92866140a6565b516126ab82896140a6565b5190806000526020906000825260406000208c6000528252826040600020546126d682821015614177565b82600052600084528d60406000209060005284520360406000205560005260008152604060002090886000525261271360406000209182546141e4565b905561408a565b612689565b509094939291938287604051604081527f4a39dc06d4c0dbc64b70af90fd698a233a518aa5d07e595d983b8c0526c8f7fb61275d604083018a613b69565b9180830360208201528061277233948b613b69565b0390a43b61277c57005b60006020946127dd6127ce976127be94604051998a988997889663bc197c8160e01b9e8f89523360048a0152602489015260a0604489015260a4880190613b69565b9084878303016064880152613b69565b91848303016084850152613555565b03925af16000918161286b575b5061284357505060016127fb61425a565b6308c379a01461280c575b6104a657005b612814614278565b8061281f5750612806565b60405162461bcd60e51b815260206004820152908190610508906024830190613555565b6001600160e01b031916146103185760405162461bcd60e51b81528061050860048201614211565b61288491925060203d81116105935761058481836133cd565b90836127ea565b60405162461bcd60e51b815260206004820152602860248201527f455243313135353a2069647320616e6420616d6f756e7473206c656e677468206044820152670dad2e6dac2e8c6d60c31b6064820152608490fd5b5086600052600160205260406000203360005260205261266f60ff604060002054169050612666565b346102db5760403660031901126102db57600435600052600460205260406000206040519061293882613361565b546001600160a01b0380821680845260a09290921c6020840152901561298a575b602082015161271090612977906001600160601b0316602435614422565b049151166106bd604051928392836135c6565b905060405161299881613361565b600354828116825260a01c602082015290612959565b346102db5760203660031901126102db576004356001600160401b0381116102db576129e0602091369060040161340b565b816129f46040519283815193849201613532565b601090820190815281900382019020546040516001600160a01b039091168152f35b346102db5760203660031901126102db57336000908152600080516020615ca6833981519152602052604090205460ff168015612a5f575b612a579061461b565b600435600b55005b50336000908152600080516020615c46833981519152602052604090205460ff16612a4e565b346102db5760203660031901126102db5760043560005260056020526020600160406000200154604051908152f35b346102db576020806003193601126102db5760405190600435612ad683613397565b60288352818301604036823760005b60148110612d2e57506000918072184f03e93ff9f4daa797ed6e38ed64bf6a1f0160401b8181811015612d20575b508590506904ee2d6d415b85acef8160201b80841015612d12575b5050662386f26fc1000080831015612d03575b506305f5e10080831015612cf4575b5061271080831015612ce5575b506064821015612cd5575b600a80921015612ccb575b60019182850191836021612b9f612b89866133f0565b95612b9760405197886133cd565b8087526133f0565b858a019890601f1901368a37850101905b612c9c575b5050506040519586936000600954612bcc81613452565b90898782169182600014612c7e575050600114612c41575b50926002959492612c1d92612c2d9895612c0c602f60f81b9384835251809388840190613532565b019384015251809386840190613532565b0103601d198101855201836133cd565b6106bd604051928284938452830190613555565b8891506009600052816000206000905b828210612c645750508601016002612be4565b80549882018401989098528a978a93909101908701612c51565b60ff1916818a01528215159092028801909101915060029050612be4565b600019019082906f181899199a1a9b1b9c1cb0b131b232b360811b8282061a835304908482612bb05750612bb5565b9260010192612b73565b9290606460029104910192612b68565b60049194920491019286612b5d565b60089194920491019286612b50565b60109194920491019286612b41565b940193909104908487612b2e565b604095500491508680612b13565b601390808203918211611d6c57600382901b916001600160fd1b03811603611d6c5760ff808311611d6c57612d67600180941b30614435565b60f0811682821603918211611d6c57612d889060f41b600f60f81b16615be3565b82841b916001600160ff1b0384168403611d6c57612dc09160001a612dad848b614455565b5360f81b6001600160f81b031916615be3565b928101809111611d6c57612ddb612de19360001a9188614455565b5361408a565b612ae5565b346102db5760003660031901126102db57604051600090600854612e0981613452565b8083526001918083169081156115505750600114612e31576106bd836106a9818703826133cd565b6008600090815260209450917ff3f7a9fe364faab93b216da50a3214154f22a0a2b415b23a84c8169e8b636ee35b828410612e78575050508101909101906106a9816114e6565b8054858501870152928501928101612e5f565b346102db5760403660031901126102db57610318612ea761330b565b336000908152600080516020615ca6833981519152602052604090205460ff168015612edf575b612ed79061461b565b602435613ee1565b50336000908152600080516020615c46833981519152602052604090205460ff16612ece565b346102db5760403660031901126102db57612f1e61330b565b6024356001600160601b038116918282036102db57336000908152600080516020615ca6833981519152602090815260409091205490936127109160ff168015613038575b612f6c9061461b565b11612fe0576001600160a01b0316918215612fa05750612f8d604051613361565b60a01b6001600160a01b03191617600355005b6064906040519062461bcd60e51b82526004820152601960248201527822a921991c9c189d1034b73b30b634b2103932b1b2b4bb32b960391b6044820152fd5b60405162461bcd60e51b815260048101849052602a60248201527f455243323938313a20726f79616c7479206665652077696c6c206578636565646044820152692073616c65507269636560b01b6064820152608490fd5b50600080516020615cc68339815191526000908152600586526040808220338352875290205460ff16612f63565b346102db576020806003193601126102db576001600160401b036004358181116102db5761309890369060040161340b565b91600080516020615c8683398151915260005260058152604060002033600052815260ff6040600020541680156131d7575b6130d39061461b565b8251918211610c0c576130e7600254613452565b601f8111613190575b5080601f831160011461312c57508192600092613121575b5050600019600383901b1c191660019190911b17600255005b015190508280613108565b90601f19831693600260005282600020926000905b868210613178575050836001951061315f575b505050811b01600255005b015160001960f88460031b161c19169055828080613154565b80600185968294968601518155019501930190613141565b600260005281600020601f840160051c8101918385106131cd575b601f0160051c01905b8181106131c157506130f0565b600081556001016131b4565b90915081906131ab565b50600080516020615cc68339815191526000908152600582526040808220338352835290205460ff166130ca565b346102db5760003660031901126102db57602060ff600a54166040519015158152f35b346102db5760203660031901126102db5760043563ffffffff60e01b81168091036102db57602090635a05180f60e01b811490811561326d575b506040519015158152f35b637965db0b60e01b811491508115613287575b5082613262565b63152a902d60e11b8114915081156132a1575b5082613280565b636cdb3d1360e11b8114915081156132d3575b81156132c2575b508261329a565b6301ffc9a760e01b149050826132bb565b6303a24d0760e21b811491506132b4565b346102db5760403660031901126102db57602061188b61330261330b565b60243590614005565b600435906001600160a01b03821682036102db57565b602435906001600160a01b03821682036102db57565b604435906001600160a01b03821682036102db57565b35906001600160a01b03821682036102db57565b604081019081106001600160401b03821117610c0c57604052565b608081019081106001600160401b03821117610c0c57604052565b606081019081106001600160401b03821117610c0c57604052565b602081019081106001600160401b03821117610c0c57604052565b601f909101601f19168101906001600160401b03821190821017610c0c57604052565b6001600160401b038111610c0c57601f01601f191660200190565b81601f820112156102db57803590613422826133f0565b9261343060405194856133cd565b828452602083830101116102db57816000926020809301838601378301015290565b90600182811c92168015613482575b602083101461346c57565b634e487b7160e01b600052602260045260246000fd5b91607f1691613461565b90604051918260008254926134a084613452565b90818452600194858116908160001461350f57506001146134cc575b50506134ca925003836133cd565b565b9093915060005260209081600020936000915b8183106134f75750506134ca935082010138806134bc565b855488840185015294850194879450918301916134df565b9150506134ca94506020925060ff191682840152151560051b82010138806134bc565b60005b8381106135455750506000910152565b8181015183820152602001613535565b9060209161356e81518092818552858086019101613532565b601f01601f1916010190565b6020613593918160405193828580945193849201613532565b8101600e81520301902090565b6020906135ba928260405194838680955193849201613532565b82019081520301902090565b6001600160a01b039091168152602081019190915260400190565b6001600160401b038111610c0c5760051b60200190565b81601f820112156102db5780359161360f836135e1565b9261361d60405194856133cd565b808452602092838086019260051b8201019283116102db578301905b828210613647575050505090565b81358152908301908301613639565b6024359081151582036102db57565b359081151582036102db57565b9080601f830112156102db578135613689816135e1565b92604091613699835195866133cd565b808552602093848087019260051b840101938185116102db57858401925b8584106136c8575050505050505090565b6001600160401b039084358281116102db5786019060c09182601f1982880301126102db57845190838201828110868211176137835786528a8101358581116102db57878c6137199284010161340b565b8252858101359485116102db576137748b959461373b8988809886010161340b565b868501526060928381013589860152608093613758858301613665565b9086015260a09361376a858301613665565b9086015201613665565b908201528152019301926136b7565b60246000634e487b7160e01b81526041600452fd5b9080601f830112156102db5781356137af816135e1565b926040916137bf835195866133cd565b808552602093848087019260051b840101938185116102db57858401925b8584106137ee575050505050505090565b6001600160401b039084358281116102db5786019060809283601f1984880301126102db5784519061381f8261337c565b8a8401358181116102db57878c6138389287010161340b565b8252858401358b830152606090818501359081116102db578b95856138658a8961386f95819a010161340b565b898601520161334d565b908201528152019301926137dd565b9080601f830112156102db57813591613896836135e1565b926040906138a6825195866133cd565b808552602093848087019260051b850101938185116102db57858101925b8584106138d5575050505050505090565b6001600160401b0384358181116102db578301916101009182601f1985880301126102db57875190838201828110828211176137835789528a8501358181116102db57878c6139269288010161340b565b8252888501359081116102db57868b6139419287010161340b565b8a82015260608085013589830152608090818601359083015260a090818601359083015260c090818601359460028610156102db578c9687966139929386015260e09384820135908601520161334d565b908201528152019301926138c4565b81601f820112156102db578035906139b8826135e1565b926040926139c8845195866133cd565b808552602091828087019260071b850101938185116102db578301915b8483106139f55750505050505090565b6080838303126102db57836080918751613a0e8161337c565b613a1786613665565b8152613a2483870161334d565b838201528886013589820152606080870135908201528152019201916139e5565b81601f820112156102db57803590613a5c826135e1565b92604092613a6c845195866133cd565b808552602091828087019260061b850101938185116102db578301915b848310613a995750505050505090565b85838303126102db578386918251613ab081613361565b613ab98661334d565b81528286013583820152815201920191613a89565b600f54811015613aed57600f6000526003602060002091020190600090565b634e487b7160e01b600052603260045260246000fd5b81601f820112156102db57803591613b1a836135e1565b92613b2860405194856133cd565b808452602092838086019260051b8201019283116102db578301905b828210613b52575050505090565b838091613b5e8461334d565b815201910190613b44565b90815180825260208080930193019160005b828110613b89575050505090565b835185529381019392810192600101613b7b565b9080601f830112156102db57813590613bb5826135e1565b92613bc360405194856133cd565b828452602092838086019160051b830101928084116102db57848301915b848310613bf15750505050505090565b82356001600160401b0381116102db578691613c128484809489010161340b565b815201920191613be1565b60009080825260209060058252604092838120338252835260ff848220541615613c475750505050565b33845192613c5484613397565b602a84528484019086368337845115613ecd5760308253845192600193841015613eb9576078602187015360295b848111613e4f5750613e1f57865192613c9a8461337c565b60428452868401946060368737845115613e0b57603086538451821015613e0b5790607860218601536041915b818311613d9d57505050613d6d57610508938693613d5193613d42604894613d199a519a8b9576020b1b1b2b9b9a1b7b73a3937b61d1030b1b1b7bab73a1604d1b8c8801525180926037880190613532565b8401917001034b99036b4b9b9b4b733903937b6329607d1b603784015251809386840190613532565b010360288101875201856133cd565b5192839262461bcd60e51b845260048401526024830190613555565b60648587519062461bcd60e51b82528060048301526024820152600080516020615c268339815191526044820152fd5b909192600f81166010811015613df7576f181899199a1a9b1b9c1cb0b131b232b360811b901a613dcd8588614455565b5360041c928015613de357600019019190613cc7565b634e487b7160e01b82526011600452602482fd5b634e487b7160e01b83526032600452602483fd5b634e487b7160e01b81526032600452602490fd5b60648688519062461bcd60e51b82528060048301526024820152600080516020615c268339815191526044820152fd5b90600f81166010811015613ea5576f181899199a1a9b1b9c1cb0b131b232b360811b901a613e7d8389614455565b5360041c908015613e915760001901613c82565b634e487b7160e01b86526011600452602486fd5b634e487b7160e01b87526032600452602487fd5b634e487b7160e01b85526032600452602485fd5b634e487b7160e01b84526032600452602484fd5b906040613f209260009080825260056020528282209360018060a01b03169384835260205260ff838320541615613f23575b8152600660205220614499565b50565b8082526005602052828220848352602052828220600160ff198254161790553384827f2f8788117e7eff1d82e926ec794901d17c78024a50270940304540a733656f0d8580a4613f13565b9060ff801983541691151516179055565b906040613f209260009080825260056020528282209360018060a01b03169384835260205260ff8383205416613fbd575b815260066020522061452b565b808252600560205282822084835260205282822060ff1981541690553384827ff6391f5c32d9c69d2a47ea670b442974b53935d1edc7fd64eb21e047a839171b8580a4613fb0565b6001600160a01b031690811561403257600052600060205260406000209060005260205260406000205490565b60405162461bcd60e51b815260206004820152602a60248201527f455243313135353a2061646472657373207a65726f206973206e6f742061207660448201526930b634b21037bbb732b960b11b6064820152608490fd5b6000198114611d6c5760010190565b805115613aed5760200190565b8051821015613aed5760209160051b010190565b156140c157565b60405162461bcd60e51b815260206004820152602e60248201527f455243313135353a2063616c6c6572206973206e6f7420746f6b656e206f776e60448201526d195c881bdc88185c1c1c9bdd995960921b6064820152608490fd5b1561412457565b60405162461bcd60e51b815260206004820152602560248201527f455243313135353a207472616e7366657220746f20746865207a65726f206164604482015264647265737360d81b6064820152608490fd5b1561417e57565b60405162461bcd60e51b815260206004820152602a60248201527f455243313135353a20696e73756666696369656e742062616c616e636520666f60448201526939103a3930b739b332b960b11b6064820152608490fd5b9060018201809211611d6c57565b91908201809211611d6c57565b908160209103126102db57516001600160e01b0319811681036102db5790565b60809060208152602860208201527f455243313135353a204552433131353552656365697665722072656a656374656040820152676420746f6b656e7360c01b60608201520190565b60009060033d1161426757565b905060046000803e60005160e01c90565b600060443d106142d557604051600319913d83016004833e81516001600160401b03918282113d6024840111176142d8578184019485519384116142e0573d850101602084870101116142d857506142d5929101602001906133cd565b90565b949350505050565b50949350505050565b9192813b6142f8575b50505050565b60209161434891600060405195868095819463f23a6e6160e01b9a8b845260018060a01b03809516600485015285602485015260448401526001606484015260a0608484015260a4830190613555565b0393165af1600091816143bb575b50614393575050600161436761425a565b6308c379a014614380575b6104a6575b388080806142f2565b614388614278565b8061281f5750614372565b6001600160e01b031916146143775760405162461bcd60e51b81528061050860048201614211565b6143d491925060203d81116105935761058481836133cd565b9038614356565b6040516143e781613361565b600181526020368183013760016143fd82614099565b5290565b6040519061440e82613361565b60018252602036818401376143fd82614099565b81810292918115918404141715611d6c57565b811561443f570490565b634e487b7160e01b600052601260045260246000fd5b908151811015613aed570160200190565b601154811015613aed57601160005260206000200190600090565b8054821015613aed5760005260206000200190600090565b9190600183016000908282528060205260408220541560001461451857845494600160401b86101561450457836144f46144dd886001604098999a01855584614481565b819391549060031b91821b91600019901b19161790565b9055549382526020522055600190565b634e487b7160e01b83526041600452602483fd5b50925050565b91908203918211611d6c57565b906001820190600092818452826020526040842054908115156000146146145760001991808301818111614600578254908482019182116145ec578082036145b7575b505050805480156145a3578201916145868383614481565b909182549160031b1b191690555582526020526040812055600190565b634e487b7160e01b8652603160"

func TestETXSmartContract(t *testing.T) {
	client, err := ethclient.Dial(wsUrl_)
	if err != nil {
		t.Fatalf("Failed to connect to the Ethereum WebSocket client: %v", err)
	}
	defer client.Close()

	cyprus2Client, err := ethclient.Dial(wsUrlCyprus2)
	if err != nil {
		t.Fatalf("Failed to connect to the Ethereum WebSocket client: %v", err)
	}
	defer cyprus2Client.Close()

	fromAddress := common.HexToAddress(quaiAddr, location)
	privKey, err := crypto.ToECDSA(common.FromHex(quaiPrivkey))
	if err != nil {
		t.Fatalf("Failed to convert private key to ECDSA: %v", err)
	}
	from := crypto.PubkeyToAddress(privKey.PublicKey, location)
	if !from.Equal(fromAddress) {
		t.Fatalf("Failed to convert public key to address: %v", err)
	}
	// Check balance
	balance, err := client.BalanceAt(context.Background(), fromAddress.MixedcaseAddress(), nil)
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	nonce, err := client.PendingNonceAt(context.Background(), fromAddress.MixedcaseAddress())
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	fmt.Printf("Balance of %s: %s nonce: %d\n", fromAddress.String(), balance.String(), nonce)

	// Deploy QXC contract with the proper address that gives me tokens in zone 0-0
	contract, err := hex.DecodeString(binary)
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	signer := types.LatestSigner(PARAMS)
	toAddr := common.ZeroAddress(common.Location{0, 1})
	// Construct deployment tx
	inner_tx := types.QuaiTx{ChainID: PARAMS.ChainID, Nonce: nonce, GasTipCap: MINERTIP, GasFeeCap: MAXFEE, Gas: 5000000, To: &toAddr, Value: common.Big0, Data: contract}
	tx, err := types.SignTx(types.NewTx(&inner_tx), signer, privKey)
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	gas, err := client.EstimateGas(context.Background(), interfaces.CallMsg{From: fromAddress /*To: nil, Gas: 0, GasPrice: MAXFEE, GasFeeCap: MAXFEE, GasTipCap: MINERTIP, Value: common.Big0, */, Data: contract, AccessList: inner_tx.AccessList})
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	fmt.Println("gas: ", gas)
	err = client.SendTransaction(context.Background(), tx)
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	//time.Sleep(1 * time.Minute) // Wait for it to be mined
	tx, isPending, err := client.TransactionByHash(context.Background(), tx.Hash())
	fmt.Printf("tx: %+v isPending: %v err: %v\n", tx, isPending, err)
	receipt, err := client.TransactionReceipt(context.Background(), tx.Hash())
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	fmt.Printf("Receipt: %+v\n", receipt)

	etx := receipt.Etxs[0]
	tx, isPending, err = cyprus2Client.TransactionByHash(context.Background(), etx.Hash())
	if err != nil {
		fmt.Println(err.Error())
	}
	fmt.Printf("etx: %+v isPending: %v err: %v\n", tx, isPending, err)
	receipt, err = cyprus2Client.TransactionReceipt(context.Background(), etx.Hash())
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	fmt.Printf("ETX Receipt: %+v\n", receipt)
	contractAddr := receipt.ContractAddress
	// Check balance in zone 0-1
	sig := crypto.Keccak256([]byte("balanceOf(address)"))[:4]
	data := make([]byte, 0, 0)
	data = append(data, sig...)
	from_, err := uint256.FromHex(from.Hex())
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	temp := from_.Bytes32()
	data = append(data, temp[:]...)

	data, err = cyprus2Client.CallContract(context.Background(), interfaces.CallMsg{To: &contractAddr, Data: data}, nil)
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	fmt.Printf("Balance of %s: %s\n", toAddr.String(), new(big.Int).SetBytes(data).String())

}

func TestSmartContract(t *testing.T) {

	client, err := ethclient.Dial(wsUrl_)
	if err != nil {
		t.Fatalf("Failed to connect to the Ethereum WebSocket client: %v", err)
	}
	defer client.Close()
	fromAddress := common.HexToAddress(quaiGenAllocAddr, location)
	privKey, err := crypto.ToECDSA(common.FromHex(quaiGenAllocPrivKey))
	if err != nil {
		t.Fatalf("Failed to convert private key to ECDSA: %v", err)
	}
	from := crypto.PubkeyToAddress(privKey.PublicKey, location)
	if !from.Equal(fromAddress) {
		t.Fatalf("Failed to convert public key to address: %v", err)
	}
	// Check balance
	balance, err := client.BalanceAt(context.Background(), fromAddress.MixedcaseAddress(), nil)
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	nonce, err := client.PendingNonceAt(context.Background(), fromAddress.MixedcaseAddress())
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	fmt.Printf("Balance of %s: %s nonce: %d\n", fromAddress.String(), balance.String(), nonce)

	// Deploy QXC contract with the proper address that gives me tokens in zone 0-0
	contract, err := hex.DecodeString(binary)
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	/*i := uint8(0)
		j := uint8(0)
		contract = append(contract, i)
		contract = append(contract, j)
		var contractAddr common.Address
		// Grind contract address
	grind:
		for {
			contract[len(contract)-2] = i
			for j = 0; j < 255; j++ {
				contract[len(contract)-1] = j
				contractAddr = crypto.CreateAddress(fromAddress, nonce, contract, location)
				if common.IsInChainScope(contractAddr.Bytes(), location) && contractAddr.IsInQuaiLedgerScope() {
					break grind
				}
			}
			i++
		}
	fmt.Println("Contract address: ", contractAddr.String())
	fmt.Println("Took ", (i+1)*(j+1), " iterations to find contract address")*/
	signer := types.LatestSigner(PARAMS)
	// Construct deployment tx
	inner_tx := types.QuaiTx{ChainID: PARAMS.ChainID, Nonce: nonce, GasTipCap: MINERTIP, GasFeeCap: MAXFEE, Gas: 5000000, To: nil, Value: common.Big0, Data: contract}
	tx, err := types.SignTx(types.NewTx(&inner_tx), signer, privKey)
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	gas, err := client.EstimateGas(context.Background(), interfaces.CallMsg{From: fromAddress /*To: nil, Gas: 0, GasPrice: MAXFEE, GasFeeCap: MAXFEE, GasTipCap: MINERTIP, Value: common.Big0, */, Data: contract, AccessList: inner_tx.AccessList})
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	fmt.Println("gas: ", gas)
	/*accessList, err := client.CreateAccessList(context.Background(), interfaces.CallMsg{From: fromAddress, Data: contract})
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	t.Logf("AccessListResult: %+v\n", accessList)
	t.Logf("AccessList: %+v\n", accessList.Accesslist)*/
	protoTx, err := tx.ProtoEncode()
	if err != nil {
		return
	}
	data, err := proto.Marshal(protoTx)
	if err != nil {
		return
	}
	fmt.Printf("%+v\n", data)
	err = client.SendTransaction(context.Background(), tx)
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	fmt.Println("tx: ", tx.Hash().String())
	fmt.Println(crypto.Keccak256(data))
	fmt.Println("tx value: ", tx.Value().String())
	//time.Sleep(5 * time.Second) // Wait for it to be mined
	newtx, isPending, err := client.TransactionByHash(context.Background(), tx.Hash())
	fmt.Println("newtx value: ", newtx.Value().String())
	newProtoTx, err := newtx.ProtoEncode()
	if err != nil {
		return
	}
	data_, err := proto.Marshal(newProtoTx)
	if err != nil {
		return
	}
	fmt.Printf("%+v\n", data_)
	fmt.Println("tx: ", newtx.Hash().String())
	fmt.Printf("tx: %+v isPending: %v err: %v\n", tx, isPending, err)
	receipt, err := client.TransactionReceipt(context.Background(), tx.Hash())
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	fmt.Printf("Receipt: %+v\n", receipt)
	contractAddr := receipt.ContractAddress

	// Check balance in zone 0-0
	sig := crypto.Keccak256([]byte("testSha()"))[:4]
	data = make([]byte, 0, 0)
	data = append(data, sig...)
	/*from_, err := uint256.FromHex(fromAddress.Hex())
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	temp := from_.Bytes32()
	data = append(data, temp[:]...)*/

	data, err = client.CallContract(context.Background(), interfaces.CallMsg{To: &contractAddr, Data: data}, nil)
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	fmt.Printf("Balance of %s: %s\n", fromAddress.String(), new(big.Int).SetBytes(data).String())

}

func TestGetBalance(t *testing.T) {
	wsClientCyprus1, err := ethclient.Dial(wsUrl_)
	if err != nil {
		t.Fatalf("Failed to connect to the Ethereum WebSocket client: %v", err)
	}
	defer wsClientCyprus1.Close()

	balance, err := wsClientCyprus1.BalanceAt(context.Background(), common.HexToAddress("0x000D8BfADBF40241101c430D25151D893c6b16D8", common.Location{0, 0}).MixedcaseAddress(), nil)
	if err != nil {
		t.Error(err.Error())
		t.Fail()
	}
	t.Log(balance)

	wsClientCyprus2, err := ethclient.Dial(wsUrlCyprus2)
	if err != nil {
		t.Fatalf("Failed to connect to the Ethereum WebSocket client: %v", err)
	}
	defer wsClientCyprus2.Close()

	balance, err = wsClientCyprus2.BalanceAt(context.Background(), common.HexToAddress("0x0109E949aF137F98bb6AF72102b9fE5C3d7e17cc", common.Location{0, 1}).MixedcaseAddress(), nil)
	if err != nil {
		t.Error(err.Error())
		t.Fail()
	}
	t.Log(balance)
}

/*func TestQiLedgerScope(t *testing.T) {

	address := common.FromHex("0x010978987B569072744dc9426E76590eb6fCfE8B")
	if !common.IsInQiLedgerScope(common.AddressBytes(address)) {
		t.Fail()
	}
	t.Log("Yes")

}*/

func getAggSig_(privKeys []*secp256k1.PrivateKey, pubKeys []*secp256k1.PublicKey, txHash [32]byte) (*schnorr.Signature, error) {
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
