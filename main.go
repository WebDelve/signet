package main

import (
	"encoding/base64"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/WebDelve/signet/keys"
	"github.com/WebDelve/signet/signing"
)

type CLIFlags struct {
	keyPath string
	txPath  string
	keyGen  bool
	sign    bool
}

func main() {
	flags := handleFlags()

	if flags.keyGen {
		key, err := keys.Generate()
		if err != nil {
			fmt.Printf("Error generating key: %v\n", err)
			os.Exit(1)
		}
		err = key.Export(flags.keyPath)
		if err != nil {
			fmt.Printf("Error exporting key: %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("Key generated and exported to %s\n", flags.keyPath)
		os.Exit(0)
	}

	if flags.sign {
		key, err := keys.Import(flags.keyPath, "RSA")
		if err != nil {
			fmt.Printf("Error importing key: %v\n", err)
			os.Exit(1)
		}

		txData, err := os.ReadFile(flags.txPath)
		if err != nil {
			fmt.Printf("Error reading transaction file: %v\n", err)
			os.Exit(1)
		}

		s := signing.New(key).
			WithTransaction(txData)

		if err := s.Sign(); err != nil {
			fmt.Printf("Error signing transaction: %v\n", err)
			os.Exit(1)
		}

		tx := s.GetTransaction()
		txRaw, err := tx.ToStringIndent()
		if err != nil {
			fmt.Printf("Error converting transaction to string: %v\n", err)
			os.Exit(1)
		}

		saveSignedTx(txRaw, flags.txPath)

		fmt.Printf("Transaction signatures: \n\n")
		for k, v := range tx.Signature {
			enc := base64.StdEncoding.EncodeToString(v.([]byte))

			fmt.Printf("Stream ID: %s\n", k)
			fmt.Printf("Signature: %s\n\n", enc)
		}

		fmt.Printf("Done\n")
		os.Exit(0)
	}

}

// saveSignedTx saves the signed transaction to a file with the
// same name as the original transaction file, with "_signed" appended
// before the file extension
func saveSignedTx(tx string, path string) {
	dir := filepath.Dir(path)
	name := strings.Split(filepath.Base(path), ".")[0]

	signedPath := filepath.Join(dir, name+"_signed.json")

	if err := os.WriteFile(signedPath, []byte(tx), 0644); err != nil {
		fmt.Printf("Error saving signed transaction: %v\n", err)
		os.Exit(1)
	}
}

func handleFlags() CLIFlags {

	// Define the flags
	keyPathPtr := flag.String("kf", "", "Path to the RSA private key PEM file")

	txPathPtr := flag.String("tx", "", "Path to the transaction file")

	keyGenPtr := flag.Bool("kg", false, "Generate a new RSA key pair")

	signPtr := flag.Bool("s", false, "Sign the transaction file")

	helpPtr := flag.Bool("h", false, "Print this message")

	// Parse the flags
	flag.Parse()

	flags := CLIFlags{
		keyPath: *keyPathPtr,
		txPath:  *txPathPtr,
		keyGen:  *keyGenPtr,
		sign:    *signPtr,
	}

	if *helpPtr {
		flag.Usage()
		os.Exit(0)
	}

	// Check if the required flags are set
	if flags.txPath == "" && flags.keyPath == "" && !flags.keyGen && !flags.sign {
		flag.Usage()
		fmt.Printf("\nMissing required flags\n\n")
		os.Exit(1)
	}

	if flags.sign && flags.txPath == "" {
		flag.Usage()
		fmt.Printf("\nMissing transaction file path\n\n")
		os.Exit(1)
	}

	if flags.keyGen && flags.keyPath == "" {
		flag.Usage()
		fmt.Printf("\nMissing key file path\n\n")
		os.Exit(1)
	}

	return flags
}
