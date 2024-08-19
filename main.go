package main

import (
	"encoding/csv"
	"flag"
	"fmt"
	"log"
	"os"
	"strconv"

	"github.com/btcsuite/btcd/btcutil"
)

type Generated struct {
	P2pkhAddress      btcutil.Address
	P2wpkhP2shAddress btcutil.Address
	P2wpkhAddress     btcutil.Address
	TaprootAddress    btcutil.Address
	Mnemonic          string
}

func main() {
	var (
		bits  = flag.Int("bits", 128, "Bit size for entropy")
		count = flag.Int("count", 1, "Count of wallets to generate")
		out   = flag.String("out", "", "Output file")
	)

	flag.Parse()

	var wallets []Generated

	for i := 0; i < *count; i++ {
		wallet, err := NewWallet(*bits)
		if err != nil {
			log.Fatalf("Error generating wallet: %v", err)
		}

		// Derive and print the BIP-44 P2PKH address
		p2pkhAddress, err := wallet.DeriveP2PKHAddress()
		if err != nil {
			log.Fatalf("Error deriving BIP-44 P2PKH address: %v", err)
		}

		// Derive and print the BIP-49 P2WPKH-in-P2SH address
		p2wpkhP2shAddress, err := wallet.DeriveP2WPKHInP2SHAddress()
		if err != nil {
			log.Fatalf("Error deriving BIP-49 P2WPKH-in-P2SH address: %v", err)
		}

		// Derive and print the BIP-84 native SegWit (P2WPKH) address
		p2wpkhAddress, err := wallet.DeriveP2WPKHAddress()
		if err != nil {
			log.Fatalf("Error deriving BIP-84 native SegWit address: %v", err)
		}

		// Derive and print the Taproot address
		taprootAddress, err := wallet.DeriveTaprootAddress()
		if err != nil {
			log.Fatalf("Error deriving Taproot address: %v", err)
		}

		wallets = append(wallets, Generated{
			P2pkhAddress:      p2pkhAddress,
			P2wpkhP2shAddress: p2wpkhP2shAddress,
			P2wpkhAddress:     p2wpkhAddress,
			TaprootAddress:    taprootAddress,
			Mnemonic:          wallet.Mnemonic,
		})
	}

	if len(*out) > 0 {
		fileName := *out

		file, err := os.Create(fileName)
		if err != nil {
			fmt.Println("Error creating file:", err)
			return
		}
		defer file.Close()

		writer := csv.NewWriter(file)
		defer writer.Flush() // Ensure all data is written to the file

		header := []string{"#", "Legacy, BIP-44 P2PKH Address", "Nested Segwit, BIP-49 P2WPKH-in-P2SH Address", "Native Segwit, BIP-84 P2WPKH Address", "Taproot, BIP-86 P2TR Address", "Mnemonic"}

		if err := writer.Write(header); err != nil {
			fmt.Println("Error writing header to file:", err)
			return
		}

		for i, wallet := range wallets {
			row := []string{
				strconv.Itoa(i + 1),
				wallet.P2pkhAddress.EncodeAddress(),
				wallet.P2wpkhP2shAddress.EncodeAddress(),
				wallet.P2wpkhAddress.EncodeAddress(),
				wallet.TaprootAddress.EncodeAddress(),
				wallet.Mnemonic,
			}

			if err := writer.Write(row); err != nil {
				fmt.Println("Error writing record to file:", err)
				return
			}
		}

		fmt.Println("Saved to:", *out)

	} else {
		for i, wallet := range wallets {
			fmt.Println("Mnemonic:", wallet.Mnemonic)

			fmt.Println("BIP-44 P2PKH Address:", wallet.P2pkhAddress)

			fmt.Println("BIP-49 P2WPKH-in-P2SH Address:", wallet.P2wpkhP2shAddress)

			fmt.Println("BIP-84 P2WPKH Address:", wallet.P2wpkhAddress)

			fmt.Println("BIP-86 P2TR Address:", wallet.TaprootAddress)

			if i != *count-1 {
				fmt.Println("")
			}
		}
	}
}
