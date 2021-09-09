package main

import (
	"bufio"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"get-tron-address/util"
	config "github.com/TRON-US/go-btfs-config"
	ic "github.com/libp2p/go-libp2p-core/crypto"
	"github.com/tron-us/go-btfs-common/crypto"
	"os"
	"strings"
)

//TXUPNSGEssm5rVziockTCjacvLWGKwsqVq
//Master public key:
//xpub661MyMwAqRbcErj3DnuAJ5kTVyLpU4t3x93BwZStgaunJwwaYhttNiBPvak3EkJTdhMJCxjifbeiVvARPYWje8cfbsZobhwvqa3aEKMiLDu
//
//{"PrivateKey":"CAISIH62lIdicSwIof8Hnc34lI5+n8mETKn2Gedw7R/dg+zy","Mnemonic":"muffin elbow monster regular burger lady thrive virtual curve mammal reflect venue","SkInBase64":"CAISIH62lIdicSwIof8Hnc34lI5+n8mETKn2Gedw7R/dg+zy","SkInHex":"7eb6948762712c08a1ff079dcdf8948e7e9fc9844ca9f619e770ed1fdd83ecf2"}
//muffin,elbow,monster,regular,burger,lady,thrive,virtual,curve,mammal,reflect,venue
//04f3dfca1db1edf2a024eb949ed92fe1254e96c50ea5d00a1e8bbf771f56a059f551cb810a1ac6914440b63839b7bceb2ed469be6c3a70acd81fba33bd5b2231e1
//04200cf458cefe3c008fa40b4d44a2afbde9a90e64ef4254fbfbe2acccf6cded18711072e54182e7744db421eeab3a34ff0f215beac22db313eb48550e709fbc23
//04f431a621b0e56d236fb55651c568724e32716afc9125824ebb3d98889e1364ab5bb9e2b00d916c09dfb873a76b9797fcaee0589256bb2418d8bd4b0d702b06e8
func main() {
	argsWithoutProg := os.Args[1:]
	if len(argsWithoutProg) == 0 {
		argsWithoutProg = getUserInput()
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
	ledgerAddressString := base64.StdEncoding.EncodeToString(ledgerAddress)
	fmt.Println("SPEED IN-APP WALLET ADDRESS:")
	fmt.Println(ledgerAddressString)

	f, err := os.OpenFile("SPEED_IN_APP_ADDRESS.txt", os.O_RDWR|os.O_CREATE|os.O_TRUNC, 0755)
	if err != nil {
		fmt.Println("Err OpenFile:", err)
	} else {
		_, err = f.WriteString(ledgerAddressString)
		if err != nil {
			fmt.Println("Err write file:", err)
		}
	}
	defer f.Close()

	fmt.Println("\nSuccess!\nPress ENTER to exit! / Нажмите ВВОД для выхода!")
	fmt.Scanf("%s", "")
}

func getUserInput() []string {
	fmt.Println("Enter the private key or 12 words to get the SPEED IN-APP wallet address. / Для получения адреса SPEED IN-APP кошелька введите ключ или 12 слов.")
	fmt.Println("Examples: / Примеры:")
	fmt.Println("muffin,elbow,monster,regular,burger,lady,thrive,virtual,curve,mammal,reflect,venue")
	fmt.Println("7eb6948762712c08a1ff079dcdf8948e7e9fc9844ca9f619e770ed1fdd83ecf2")
	fmt.Println("CAISIH62lIdicSwIof8Hnc34lI5+n8mETKn2Gedw7R/dg+zy")
	fmt.Println("Muffin Elbow Monster Regular Burger Lady Thrive Virtual Curve Mammal Reflect Venue")
	fmt.Println("\nEnter data from the wallet: / Введите данные от кошелька:")

	scanner := bufio.NewScanner(os.Stdin)
	scanner.Scan()
	userInput := scanner.Text()

	count := 0
	for _, ch := range userInput {
		if ch == ' ' || ch == ',' {
			count++
		}
	}

	if count == 11 {
		userInput = strings.ToLower(userInput)
		userInput = strings.ReplaceAll(userInput, " ", ",")
		return []string{"seed", userInput}
	}

	return []string{"key", userInput}
}

func help() {
	fmt.Println("Example / Пример запуска из командной строки:")
	fmt.Println("address.exe seed muffin,elbow,monster,regular,burger,lady,thrive,virtual,curve,mammal,reflect,venue")
	fmt.Println("OR / ИЛИ")
	fmt.Println("address.exe key 7eb6948762712c08a1ff079dcdf8948e7e9fc9844ca9f619e770ed1fdd83ecf2")
	os.Exit(1)
}
