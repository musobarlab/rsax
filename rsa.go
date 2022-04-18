package rsax

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"io"
	"io/ioutil"
	"os"
)

const (
	DefaultKeySize = 1 << 12
)

type Key struct {
	PrivateKey      *rsa.PrivateKey
	PublicKey       *rsa.PublicKey
	PrivateKeyBytes []byte
	PublicKeyBytes  []byte
}

func GenerateKey(keySize int) (*Key, error) {
	if keySize < 1024 {
		keySize = DefaultKeySize
	}
	privateKey, err := rsa.GenerateKey(rand.Reader, keySize)
	if err != nil {
		return nil, err
	}

	publicKey := privateKey.PublicKey

	privateKeyBytes := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
		},
	)

	pubASN1, err := x509.MarshalPKIXPublicKey(&publicKey)
	if err != nil {
		return nil, err
	}

	publicKeyBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubASN1,
	})

	return &Key{
		PrivateKey:      privateKey,
		PublicKey:       &publicKey,
		PrivateKeyBytes: privateKeyBytes,
		PublicKeyBytes:  publicKeyBytes,
	}, nil

}

func (k *Key) GetPrivateKeyHexStr() string {
	return hex.EncodeToString(k.PrivateKeyBytes)
}

func (k *Key) GetPublicKeyHexStr() string {
	return hex.EncodeToString(k.PublicKeyBytes)
}

func EncryptWithOAEP(message []byte, publicKey *rsa.PublicKey) ([]byte, error) {
	msgHash := sha512.New()
	ciphertextBytes, err := rsa.EncryptOAEP(msgHash, rand.Reader, publicKey, message, nil)
	if err != nil {
		return nil, err
	}

	return ciphertextBytes, nil
}

func EncryptWithOAEPToBase64Str(message []byte, publicKey *rsa.PublicKey) ([]byte, error) {
	ciphertextBytes, err := EncryptWithOAEP(message, publicKey)
	if err != nil {
		return nil, err
	}

	return []byte(base64.StdEncoding.EncodeToString(ciphertextBytes)), nil
}

func DecryptWithOAEP(ciphertextBytes []byte, privateKey *rsa.PrivateKey) ([]byte, error) {
	msgHash := sha512.New()
	plaintext, err := rsa.DecryptOAEP(msgHash, rand.Reader, privateKey, ciphertextBytes, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

func DecryptWithOAEPFromBase64Str(ciphertextBase64 string, privateKey *rsa.PrivateKey) ([]byte, error) {
	cipertextBytes, err := base64.StdEncoding.DecodeString(ciphertextBase64)
	if err != nil {
		return nil, err
	}

	plaintext, err := DecryptWithOAEP(cipertextBytes, privateKey)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

func SignWithPSS(message []byte, privateKey *rsa.PrivateKey) ([]byte, error) {
	msgHashSum, err := hashSha512(message)
	if err != nil {
		return nil, err
	}

	signature, err := rsa.SignPSS(rand.Reader, privateKey, crypto.SHA512, msgHashSum, nil)
	if err != nil {
		return nil, err
	}

	return signature, nil
}

func VerifyWithPSS(message, signature []byte, publicKey *rsa.PublicKey) error {
	msgHashSum, err := hashSha512(message)
	if err != nil {
		return err
	}

	err = rsa.VerifyPSS(publicKey, crypto.SHA512, msgHashSum, signature, nil)
	if err != nil {
		return err
	}

	return nil
}

func ParseRSAPrivateKeyFromReader(reader io.Reader) (*rsa.PrivateKey, error) {
	privateKeyData, err := ioutil.ReadAll(reader)
	if err != nil {
		return nil, err
	}

	privateKey, err := ParseRSAPrivateKey(privateKeyData)
	if err != nil {
		return nil, err
	}

	return privateKey, nil
}

func ParseRSAPublicKeyFromReader(reader io.Reader) (*rsa.PublicKey, error) {
	publicKeyData, err := ioutil.ReadAll(reader)
	if err != nil {
		return nil, err
	}

	publicKey, err := ParseRSAPublicKey(publicKeyData)
	if err != nil {
		return nil, err
	}

	return publicKey, nil
}

func ParseRSAPrivateKeyFromFile(fileName string) (*rsa.PrivateKey, error) {
	f, err := os.Open(fileName)
	if err != nil {
		return nil, err
	}

	defer func() { f.Close() }()

	privateKey, err := ParseRSAPrivateKeyFromReader(f)
	if err != nil {
		return nil, err
	}

	return privateKey, nil
}

func ParseRSAPublicKeyFromFile(fileName string) (*rsa.PublicKey, error) {
	f, err := os.Open(fileName)
	if err != nil {
		return nil, err
	}

	defer func() { f.Close() }()

	publicKey, err := ParseRSAPublicKeyFromReader(f)
	if err != nil {
		return nil, err
	}

	return publicKey, nil
}

func ParseRSAPrivateKeyFromHex(privateKeyHex []byte) (*rsa.PrivateKey, error) {
	privateKeyData := make([]byte, hex.DecodedLen(len(privateKeyHex)))
	n, err := hex.Decode(privateKeyData, privateKeyHex)
	if err != nil {
		return nil, err
	}

	privateKey, err := ParseRSAPrivateKey(privateKeyData[:n])
	if err != nil {
		return nil, err
	}

	return privateKey, nil
}

func ParseRSAPublicKeyFromHex(publicKeyHex []byte) (*rsa.PublicKey, error) {
	publicKeyData := make([]byte, hex.DecodedLen(len(publicKeyHex)))
	n, err := hex.Decode(publicKeyData, publicKeyHex)
	if err != nil {
		return nil, err
	}

	publicKey, err := ParseRSAPublicKey(publicKeyData[:n])
	if err != nil {
		return nil, err
	}

	return publicKey, nil
}

func ParseRSAPrivateKey(privateKeyData []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(privateKeyData)

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return privateKey, nil
}

func ParseRSAPublicKey(publicKeyData []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(publicKeyData)

	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	rsaPublicKey, ok := publicKey.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("error: public key is not valid RSA Public Key")
	}

	return rsaPublicKey, nil
}

func hashSha512(message []byte) ([]byte, error) {
	msgHash := sha512.New()

	_, err := msgHash.Write(message)
	if err != nil {
		return nil, err
	}

	msgHashSum := msgHash.Sum(nil)
	return msgHashSum, nil
}

func hashSha256(message []byte) ([]byte, error) {
	msgHash := sha256.New()

	_, err := msgHash.Write(message)
	if err != nil {
		return nil, err
	}

	msgHashSum := msgHash.Sum(nil)
	return msgHashSum, nil
}
