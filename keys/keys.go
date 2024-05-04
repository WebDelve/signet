package keys

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
)

const BITSIZE = 2048

type KeyHandler interface {
	Export() error
	Sign(data []byte) (signature []byte, digest []byte, signErr error)
	Verify(checksum []byte, signature []byte) error
}

type RSA struct {
	privateKey *rsa.PrivateKey
	pubPem     []byte
	prvPem     []byte
}

func Generate() (KeyHandler, error) {
	r := RSA{}
	if err := r.generateKey(); err != nil {
		return nil, err
	}

	return &r, nil
}

func Import(path string, keyType string) KeyHandler {
	return &RSA{}
}

func (r *RSA) Export() error {
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
