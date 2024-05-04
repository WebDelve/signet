# Signet
Activeledger CLI Signing tool

## Usage

### Build from source

```bash
go build -o ./bin/signet
```

### Generate a keypair

```bash
signet -kg -kf mypemfile.pem
```

### Sign a transaction

```bash
signet -s -kf mypemfile.pem -tf transaction.json
```

Your signed transaction will be output to the console, and will be output
to a file named `transaction_signed.json` in the same path as the original.

**Note** that the original transaction file will not be modified.

**Note** that the file will have _signed appended to the filename.

