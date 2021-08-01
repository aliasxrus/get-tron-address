package main

import (
	"encoding/hex"
	"fmt"
	"get-tron-address/util"
	config "github.com/TRON-US/go-btfs-config"
	ic "github.com/libp2p/go-libp2p-core/crypto"
	"github.com/tron-us/go-btfs-common/crypto"
	"os"
	"strings"
)

func main() {
	argsWithoutProg := os.Args[1:]
	if len(argsWithoutProg) == 0 {
		help()
	}

	var k string
	switch argsWithoutProg[0] {
	case "seed": // Seed phrase
		key, mnemonic, err := util.GenerateKey("", "BIP39", argsWithoutProg[1])
		fmt.Println("Mnemonic:", strings.ReplaceAll(mnemonic, " ", ","))
		if err != nil {
			fmt.Println("Error:", err)
			os.Exit(1)
		}
		k = key
	case "key": // TRON private key
		key, mnemonic, err := util.GenerateKey(argsWithoutProg[1], "secp256k1", "")
		fmt.Println("Mnemonic:", strings.ReplaceAll(mnemonic, " ", ","))
		if err != nil {
			fmt.Println("Error:", err)
			os.Exit(1)
		}
		k = key
	default:
		help()
	}

	var identity config.Identity
	ks, err := crypto.FromPrivateKey(k)
	if err != nil {
		fmt.Println("Error:", err)
		os.Exit(1)
	}
	fmt.Println("TRON address:", ks.Base58Address)

	k64, err := crypto.Hex64ToBase64(ks.HexPrivateKey)
	identity.PrivKey = k64
	if err != nil {
		fmt.Println("Error:", err)
		os.Exit(1)
	}
	fmt.Println("PrivateKey:", ks.HexPrivateKey)
	fmt.Println("SkInBase64:", k64)

	// get key
	privKeyIC, err := identity.DecodePrivateKey("")
	if err != nil {
		fmt.Println("wallet get private key failed")
		fmt.Println("Error:", err)
		os.Exit(1)
	}

	// base64 key
	privKeyRaw, err := privKeyIC.Raw()
	if err != nil {
		fmt.Println("wallet get private key raw failed")
		fmt.Println("Error:", err)
		os.Exit(1)
	}

	// hex key
	hexPrivKey := hex.EncodeToString(privKeyRaw)

	// hex key to ecdsa
	privateKey, err := crypto.HexToECDSA(hexPrivKey)
	if err != nil {
		fmt.Println("error when convent private key to edca")
		fmt.Println("Error:", err)
		os.Exit(1)
	}
	if privateKey == nil {
		fmt.Println("wallet get private key ecdsa failed")
		fmt.Println("Error:", err)
		os.Exit(1)
	}

	ledgerAddress, err := ic.RawFull(privKeyIC.GetPublic())
	if err != nil {
		fmt.Println("Error:", err)
		os.Exit(1)
	}
	ledgerAddressString := hex.EncodeToString(ledgerAddress)
	fmt.Println("Speed address:", ledgerAddressString)
	fmt.Println("\nSuccess!")
}

func help() {
	fmt.Println("Example:")
	fmt.Println("address.exe seed muffin,elbow,monster,regular,burger,lady,thrive,virtual,curve,mammal,reflect,venue")
	fmt.Println("OR")
	fmt.Println("address.exe key 7eb6948762712c08a1ff079dcdf8948e7e9fc9844ca9f619e770ed1fdd83ecf2")
	os.Exit(1)
}
