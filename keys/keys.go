package keys

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"os"
)

const BITSIZE = 2048

type KeyHandler interface {
	// Export the private key in PEM form to the given path
	Export(path string) error

	// Sign the given data and return the signature and the digest
	Sign(data []byte) (signature []byte, digest []byte, signErr error)

	// Verify the signature of the given checksum
	Verify(checksum []byte, signature []byte) error
}

type RSA struct {
	privateKey *rsa.PrivateKey
	pubPem     []byte
	prvPem     []byte
}

// Generate a new RSA key pair
func Generate() (KeyHandler, error) {
	r := RSA{}
	if err := r.generateKey(); err != nil {
		return nil, err
	}

	return &r, nil
}

// Import a RSA Private key (PEM) from the given path
func Import(path string, keyType string) (KeyHandler, error) {
	prvPem, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	pKey, err := pemToKey(prvPem)
	if err != nil {
		return nil, err
	}

	r := RSA{
		privateKey: pKey,
		prvPem:     prvPem,
	}

	if err := r.pubToPem(); err != nil {
		return nil, err
	}

	return &r, nil
}

func (r *RSA) Export(path string) error {
	if err := os.WriteFile(path, r.prvPem, 0644); err != nil {
		return err
	}

	return nil
}

func (r *RSA) Sign(d []byte) ([]byte, []byte, error) {
	h := sha256.New()
	h.Write(d)
	digest := h.Sum(nil)

	sig, err := r.privateKey.Sign(rand.Reader, digest, crypto.SHA256)
	if err != nil {
		return nil, nil, err
	}

	if err := r.Verify(digest, sig); err != nil {
		return nil, nil, err
	}

	return sig, digest, nil
}

func (r *RSA) Verify(sum []byte, sig []byte) error {
	if err := rsa.VerifyPKCS1v15(&r.privateKey.PublicKey, crypto.SHA256, sum, sig); err != nil {
		return err
	}

	return nil
}

// Generate the private key and setup the key data
func (r *RSA) generateKey() error {
	reader := rand.Reader
	k, err := rsa.GenerateKey(reader, BITSIZE)
	if err != nil {
		return err
	}

	r.privateKey = k

	if err := r.pubToPem(); err != nil {
		return err
	}

	r.prvToPem()

	return nil
}

// Convert the public key to PEM format
func (r *RSA) pubToPem() error {
	bytes, err := x509.MarshalPKIXPublicKey(&r.privateKey.PublicKey)
	if err != nil {
		return err
	}

	p := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: bytes,
		},
	)

	r.pubPem = p

	return nil
}

// Convert the private key to PEM format
func (r *RSA) prvToPem() {
	bytes := x509.MarshalPKCS1PrivateKey(r.privateKey)
	p := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: bytes,
		},
	)

	r.prvPem = p
}

// Convert the PEM data to an RSA private key
func pemToKey(pemData []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, nil
	}

	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return key, nil
}
