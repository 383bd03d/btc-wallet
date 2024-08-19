package main

import (
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/tyler-smith/go-bip39"
)

type Wallet struct {
	Entropy   []byte
	Mnemonic  string
	Seed      []byte
	MasterKey *hdkeychain.ExtendedKey
}

func NewWallet(bitSize int) (*Wallet, error) {
	// Generate a new mnemonic seed
	entropy, err := bip39.NewEntropy(bitSize)
	if err != nil {
		return nil, fmt.Errorf(fmt.Sprintf("Error generating entropy: %v", err))
	}

	mnemonic, err := bip39.NewMnemonic(entropy)
	if err != nil {
		return nil, fmt.Errorf(fmt.Sprintf("Error generating mnemonic: %v", err))
	}

	// Generate a Bip32 HD wallet for the mnemonic and a user-supplied password
	seed := bip39.NewSeed(mnemonic, "")

	masterKey, err := hdkeychain.NewMaster(seed, &chaincfg.MainNetParams)
	if err != nil {
		return nil, fmt.Errorf(fmt.Sprintf("Error generating master key: %v", err))
	}

	return &Wallet{
		Entropy:   entropy,
		Mnemonic:  mnemonic,
		Seed:      seed,
		MasterKey: masterKey,
	}, nil
}

func (w *Wallet) ExtendMasterKey(bip uint32) (*hdkeychain.ExtendedKey, error) {
	purpose, err := w.MasterKey.Derive(hdkeychain.HardenedKeyStart + bip) // m/44'
	if err != nil {
		return nil, fmt.Errorf("error deriving purpose: %w", err)
	}

	coinType, err := purpose.Derive(hdkeychain.HardenedKeyStart + 0) // m/44'/0'
	if err != nil {
		return nil, fmt.Errorf("error deriving coin type: %w", err)
	}

	account, err := coinType.Derive(hdkeychain.HardenedKeyStart + 0) // m/44'/0'/0'
	if err != nil {
		return nil, fmt.Errorf("error deriving account: %w", err)
	}

	change, err := account.Derive(0) // m/44'/0'/0'/0
	if err != nil {
		return nil, fmt.Errorf("error deriving change: %w", err)
	}

	addressIndex, err := change.Derive(0) // m/44'/0'/0'/0/0
	if err != nil {
		return nil, fmt.Errorf("error deriving address index: %w", err)
	}

	return addressIndex, nil
}

// deriveP2PKHAddress derives the first P2PKH address using the BIP-44 path: m/44'/0'/0'/0/0
func (w *Wallet) DeriveP2PKHAddress() (btcutil.Address, error) {
	addressIndex, err := w.ExtendMasterKey(44)
	if err != nil {
		return nil, fmt.Errorf("error extending master key: %w", err)
	}

	// Convert to a Bitcoin address (P2PKH)
	address, err := addressIndex.Address(&chaincfg.MainNetParams)
	if err != nil {
		return nil, fmt.Errorf("error generating address: %w", err)
	}

	return address, nil
}

// deriveP2WPKHInP2SHAddress derives the first P2WPKH-in-P2SH address using the BIP-49 path: m/49'/0'/0'/0/0
func (w *Wallet) DeriveP2WPKHInP2SHAddress() (btcutil.Address, error) {
	addressIndex, err := w.ExtendMasterKey(49)
	if err != nil {
		return nil, fmt.Errorf("error extending master key: %w", err)
	}

	// Extract the public key
	pubKey, err := addressIndex.ECPubKey()
	if err != nil {
		return nil, fmt.Errorf("error getting public key: %w", err)
	}

	// Generate the witness program (Hash160 of the public key)
	pubKeyHash := btcutil.Hash160(pubKey.SerializeCompressed())

	// Create the P2WPKH address
	witnessPubKeyHash, err := btcutil.NewAddressWitnessPubKeyHash(pubKeyHash, &chaincfg.MainNetParams)
	if err != nil {
		return nil, fmt.Errorf("error generating P2WPKH address: %w", err)
	}

	// Create the P2SH script
	script, err := txscript.PayToAddrScript(witnessPubKeyHash)
	if err != nil {
		return nil, fmt.Errorf("error creating P2SH script: %w", err)
	}

	// Create the P2SH address
	p2shAddress, err := btcutil.NewAddressScriptHash(script, &chaincfg.MainNetParams)
	if err != nil {
		return nil, fmt.Errorf("error generating P2SH address: %w", err)
	}

	return p2shAddress, nil
}

// deriveP2WPKHAddress derives the first native SegWit (P2WPKH) address using the BIP-84 path: m/84'/0'/0'/0/0
func (w *Wallet) DeriveP2WPKHAddress() (btcutil.Address, error) {
	addressIndex, err := w.ExtendMasterKey(84)
	if err != nil {
		return nil, fmt.Errorf("error extending master key: %w", err)
	}

	// Extract the public key
	pubKey, err := addressIndex.ECPubKey()
	if err != nil {
		return nil, fmt.Errorf("error getting public key: %w", err)
	}

	// Generate the witness program (Hash160 of the public key)
	pubKeyHash := btcutil.Hash160(pubKey.SerializeCompressed())

	// Create the native SegWit (P2WPKH) address
	witnessPubKeyHash, err := btcutil.NewAddressWitnessPubKeyHash(pubKeyHash, &chaincfg.MainNetParams)
	if err != nil {
		return nil, fmt.Errorf("error generating P2WPKH address: %w", err)
	}

	return witnessPubKeyHash, nil
}

// deriveTaprootAddress derives the first Taproot address using the BIP-86 path: m/86'/0'/0'/0/0
func (w *Wallet) DeriveTaprootAddress() (btcutil.Address, error) {
	addressIndex, err := w.ExtendMasterKey(86)
	if err != nil {
		return nil, fmt.Errorf("error extending master key: %w", err)
	}

	// Extract the public key
	pubKey, err := addressIndex.ECPubKey()
	if err != nil {
		return nil, fmt.Errorf("error getting public key: %w", err)
	}

	tapKey := txscript.ComputeTaprootKeyNoScript(pubKey)

	// Create the Taproot address
	taprootAddress, err := btcutil.NewAddressTaproot(schnorr.SerializePubKey(tapKey), &chaincfg.MainNetParams)
	if err != nil {
		return nil, fmt.Errorf("error generating Taproot address: %w", err)
	}

	return taprootAddress, nil
}
