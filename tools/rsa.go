package tools

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
)

func GenRsaKey() (prvkey, pubkey []byte) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		println(err.Error())
		return
	}
	if privateKey == nil {
		println("privateKey为空")
		return
	}
	derStream := x509.MarshalPKCS1PrivateKey(privateKey)
	block := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: derStream,
	}
	prvkey = pem.EncodeToMemory(block)

	publicKey := &privateKey.PublicKey
	derPkix, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		println(err.Error())
		return
	}
	block = &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: derPkix,
	}
	pubkey = pem.EncodeToMemory(block)

	return
}

func RsaSignWithSha256(data, prvKey []byte) ([]byte, error) {
	h := sha256.New()
	h.Write(data)
	hashed := h.Sum(nil)
	block, _ := pem.Decode(prvKey)
	if block == nil {
		return nil, errors.New("private key error")
	}

	prvKeyInterface, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	sign, err := rsa.SignPKCS1v15(rand.Reader, prvKeyInterface, crypto.SHA256, hashed)
	if err != nil {
		return nil, err
	}

	return sign, nil
}

func RsaVerifySign(data, sign, pubkey []byte) bool {
	block, _ := pem.Decode(pubkey)
	if block == nil {
		return false
	}

	pubKeyInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return false
	}

	hashed := sha256.Sum256(data)
	err = rsa.VerifyPKCS1v15(pubKeyInterface.(*rsa.PublicKey), crypto.SHA256, hashed[:], sign)
	if err != nil {
		return false
	}

	return true
}

func RsaEncrypt(data, pubkey []byte) ([]byte, error) {
	block, _ := pem.Decode(pubkey)
	if block == nil {
		return nil, errors.New("public key error")
	}

	pubKeyInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	ciphertext, err := rsa.EncryptPKCS1v15(rand.Reader, pubKeyInterface.(*rsa.PublicKey), data)
	if err != nil {
		return nil, err
	}

	return ciphertext, nil
}

func RsaDecrypt(ciphertext, prvKey []byte) ([]byte, error) {
	block, _ := pem.Decode(prvKey)
	if block == nil {
		return nil, errors.New("private key error")
	}

	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	data, err := rsa.DecryptPKCS1v15(rand.Reader, priv, ciphertext)
	if err != nil {
		return nil, err
	}

	return data, nil
}
