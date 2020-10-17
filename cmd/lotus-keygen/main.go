package main

import (
	"encoding/json"
	"fmt"
	"github.com/cosmos/cosmos-sdk/crypto/keys/hd"
	"github.com/filecoin-project/lotus/api"
	"github.com/tendermint/tendermint/crypto/secp256k1"
	"os"

	"github.com/cosmos/go-bip39"
	"github.com/filecoin-project/lotus/chain/types"
	"github.com/filecoin-project/lotus/chain/wallet"
	_ "github.com/filecoin-project/lotus/lib/sigs/bls"
	_ "github.com/filecoin-project/lotus/lib/sigs/secp"
	"github.com/urfave/cli/v2"
)

func main() {

	app := cli.NewApp()
	app.Flags = []cli.Flag{
		&cli.StringFlag{
			Name:    "type",
			Aliases: []string{"t"},
			Value:   "secp256k1",
			Usage:   "specify key type to generate (bls or secp256k1)",
		},
	}
	app.Action = func(cctx *cli.Context) error {
		memks := wallet.NewMemKeyStore()
		w, err := wallet.NewWallet(memks)
		if err != nil {
			return err
		}

		var kt types.KeyType
		switch cctx.String("type") {
		case "bls":
			kt = types.KTBLS
		case "secp256k1":
			kt = types.KTSecp256k1
		default:
			return fmt.Errorf("unrecognized key type: %q", cctx.String("type"))
		}

		// cosmos mnemonic handler
		mnemonic := "fit hint laugh oil power ahead insane rally flag car legal fix avoid lamp secret police involve enable paper birth reduce obey pudding ridge"
		// coinType 364 is lambda type, should change to filecoin type number
		hdParams := hd.NewParams(44, 364, 0, false, 1)
		seed, err := bip39.MnemonicToByteArray(mnemonic)
		if err != nil {
			fmt.Println("bip39 mnemonic to array error: ", err)
			os.Exit(1)
		}
		masterPriv, ch := hd.ComputeMastersFromSeed(seed)
		derivedPriv, err := hd.DerivePrivateKeyForPath(masterPriv, ch, hdParams.String())
		if err != nil {
			fmt.Println("DerivePrivateKeyForPath error: ", err)
			os.Exit(1)
		}
		priKey := secp256k1.PrivKeySecp256k1(derivedPriv)

		// test wallet for kangbo
		kaddr, err := w.WalletNewKB(cctx.Context, kt, priKey[:])
		if err != nil {
			fmt.Println("WalletNewKB error: ", err)
			os.Exit(1)
		}

		// sign message
		// may be use WalletSignMessage
		signMessage := []byte("hello world")
		signature, err := w.WalletSign(cctx.Context, kaddr, signMessage, api.MsgMeta{})
		if err != nil {
			fmt.Println("WalletSign error: ", err)
		}
		fmt.Printf("success signature is: %x \n", signature.Data)

		// export privateKey on desk
		ki, err := w.WalletExport(cctx.Context, kaddr)
		if err != nil {
			return err
		}

		fi, err := os.Create(fmt.Sprintf("%s.key", kaddr))
		if err != nil {
			return err
		}
		defer func() {
			err2 := fi.Close()
			if err == nil {
				err = err2
			}
		}()

		b, err := json.Marshal(ki)
		if err != nil {
			return err
		}

		if _, err := fi.Write(b); err != nil {
			return fmt.Errorf("failed to write key info to file: %w", err)
		}

		fmt.Println("Generated new key: ", kaddr)
		return nil
	}

	if err := app.Run(os.Args); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
