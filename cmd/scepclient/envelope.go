package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"

	"github.com/smallstep/pkcs7"
)

// The pkcs7 library only encrypts with DES-CBC, AES-128 and AES-256, and only
// decrypts those plus DES-EDE3. This file builds and opens CMS EnvelopedData
// (RFC 5652, section 6) with AES-CBC of any key size, so AES-192 works too.

var (
	oidAES128CBC = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 2}
	oidAES192CBC = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 22}
	oidAES256CBC = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 42}
)

// aesCBC is an AES-CBC content encryption algorithm.
type aesCBC struct {
	oid    asn1.ObjectIdentifier
	keyLen int
}

var aesCBCAlgorithms = []aesCBC{
	{oid: oidAES128CBC, keyLen: 16},
	{oid: oidAES192CBC, keyLen: 24},
	{oid: oidAES256CBC, keyLen: 32},
}

func aesCBCByOID(oid asn1.ObjectIdentifier) (aesCBC, bool) {
	for _, alg := range aesCBCAlgorithms {
		if alg.oid.Equal(oid) {
			return alg, true
		}
	}
	return aesCBC{}, false
}

type contentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,optional,tag:0"`
}

type envelopedData struct {
	Version              int
	RecipientInfos       []recipientInfo `asn1:"set"`
	EncryptedContentInfo encryptedContentInfo
}

type recipientInfo struct {
	Version                int
	IssuerAndSerialNumber  issuerAndSerial
	KeyEncryptionAlgorithm pkix.AlgorithmIdentifier
	EncryptedKey           []byte
}

type issuerAndSerial struct {
	IssuerName   asn1.RawValue
	SerialNumber *big.Int
}

type encryptedContentInfo struct {
	ContentType                asn1.ObjectIdentifier
	ContentEncryptionAlgorithm pkix.AlgorithmIdentifier
	EncryptedContent           asn1.RawValue `asn1:"tag:0,optional"`
}

// encrypt wraps content in a DER encoded EnvelopedData readable by every
// recipient. The content key is transported with RSA PKCS #1 v1.5, as in SCEP.
func (alg aesCBC) encrypt(content []byte, recipients []*x509.Certificate) ([]byte, error) {
	key := make([]byte, alg.keyLen)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	ciphertext := pkcs7Pad(content, aes.BlockSize)
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ciphertext, ciphertext)

	ivParam, err := asn1.Marshal(iv)
	if err != nil {
		return nil, err
	}

	recipientInfos := make([]recipientInfo, len(recipients))
	for i, recipient := range recipients {
		pub, ok := recipient.PublicKey.(*rsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("envelope: recipient %q does not have an RSA key", recipient.Subject)
		}
		encryptedKey, err := rsa.EncryptPKCS1v15(rand.Reader, pub, key)
		if err != nil {
			return nil, err
		}
		recipientInfos[i] = recipientInfo{
			Version: 0,
			IssuerAndSerialNumber: issuerAndSerial{
				IssuerName:   asn1.RawValue{FullBytes: recipient.RawIssuer},
				SerialNumber: recipient.SerialNumber,
			},
			KeyEncryptionAlgorithm: pkix.AlgorithmIdentifier{
				Algorithm:  pkcs7.OIDEncryptionAlgorithmRSA,
				Parameters: asn1.NullRawValue,
			},
			EncryptedKey: encryptedKey,
		}
	}

	inner, err := asn1.Marshal(envelopedData{
		Version:        0,
		RecipientInfos: recipientInfos,
		EncryptedContentInfo: encryptedContentInfo{
			ContentType: pkcs7.OIDData,
			ContentEncryptionAlgorithm: pkix.AlgorithmIdentifier{
				Algorithm:  alg.oid,
				Parameters: asn1.RawValue{FullBytes: ivParam},
			},
			EncryptedContent: asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, Bytes: ciphertext},
		},
	})
	if err != nil {
		return nil, err
	}

	return asn1.Marshal(contentInfo{
		ContentType: pkcs7.OIDEnvelopedData,
		Content:     asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, Bytes: inner, IsCompound: true},
	})
}

// decryptEnvelope opens a DER encoded, AES-CBC encrypted EnvelopedData
// addressed to cert, using its RSA private key.
func decryptEnvelope(der []byte, cert *x509.Certificate, key *rsa.PrivateKey) ([]byte, error) {
	var ci contentInfo
	if rest, err := asn1.Unmarshal(der, &ci); err != nil {
		return nil, fmt.Errorf("envelope: parse content info: %w", err)
	} else if len(rest) != 0 {
		return nil, errors.New("envelope: trailing data after content info")
	}
	if !ci.ContentType.Equal(pkcs7.OIDEnvelopedData) {
		return nil, fmt.Errorf("envelope: unexpected content type %s", ci.ContentType)
	}
	var ed envelopedData
	if _, err := asn1.Unmarshal(ci.Content.Bytes, &ed); err != nil {
		return nil, fmt.Errorf("envelope: parse enveloped data: %w", err)
	}

	var recipient *recipientInfo
	for i := range ed.RecipientInfos {
		ias := ed.RecipientInfos[i].IssuerAndSerialNumber
		if bytes.Equal(ias.IssuerName.FullBytes, cert.RawIssuer) && ias.SerialNumber.Cmp(cert.SerialNumber) == 0 {
			recipient = &ed.RecipientInfos[i]
			break
		}
	}
	if recipient == nil {
		return nil, errors.New("envelope: no recipient info for the signer certificate")
	}
	if !recipient.KeyEncryptionAlgorithm.Algorithm.Equal(pkcs7.OIDEncryptionAlgorithmRSA) {
		return nil, fmt.Errorf("envelope: unsupported key encryption algorithm %s", recipient.KeyEncryptionAlgorithm.Algorithm)
	}

	eci := ed.EncryptedContentInfo
	alg, ok := aesCBCByOID(eci.ContentEncryptionAlgorithm.Algorithm)
	if !ok {
		return nil, fmt.Errorf("envelope: unsupported content encryption algorithm %s", eci.ContentEncryptionAlgorithm.Algorithm)
	}

	contentKey, err := rsa.DecryptPKCS1v15(nil, key, recipient.EncryptedKey)
	if err != nil {
		return nil, fmt.Errorf("envelope: decrypt content key: %w", err)
	}
	if len(contentKey) != alg.keyLen {
		return nil, errors.New("envelope: content key has the wrong length")
	}

	var iv []byte
	if _, err := asn1.Unmarshal(eci.ContentEncryptionAlgorithm.Parameters.FullBytes, &iv); err != nil {
		return nil, fmt.Errorf("envelope: parse IV: %w", err)
	}
	if len(iv) != aes.BlockSize {
		return nil, errors.New("envelope: IV has the wrong length")
	}

	ciphertext, err := encryptedContentBytes(eci.EncryptedContent)
	if err != nil {
		return nil, err
	}
	if len(ciphertext) == 0 || len(ciphertext)%aes.BlockSize != 0 {
		return nil, errors.New("envelope: ciphertext is not a multiple of the block size")
	}

	block, err := aes.NewCipher(contentKey)
	if err != nil {
		return nil, err
	}
	plaintext := make([]byte, len(ciphertext))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(plaintext, ciphertext)

	return pkcs7Unpad(plaintext, aes.BlockSize)
}

// encryptedContentBytes returns the ciphertext of an [0] IMPLICIT OCTET STRING,
// which BER allows to be split into a constructed sequence of OCTET STRINGs.
func encryptedContentBytes(v asn1.RawValue) ([]byte, error) {
	if !v.IsCompound {
		return v.Bytes, nil
	}
	var buf bytes.Buffer
	rest := v.Bytes
	for len(rest) > 0 {
		var part []byte
		var err error
		if rest, err = asn1.Unmarshal(rest, &part); err != nil {
			return nil, fmt.Errorf("envelope: parse encrypted content: %w", err)
		}
		buf.Write(part)
	}
	return buf.Bytes(), nil
}

func pkcs7Pad(data []byte, blockSize int) []byte {
	padLen := blockSize - len(data)%blockSize
	padded := make([]byte, len(data), len(data)+padLen)
	copy(padded, data)
	return append(padded, bytes.Repeat([]byte{byte(padLen)}, padLen)...)
}

func pkcs7Unpad(data []byte, blockSize int) ([]byte, error) {
	if len(data) == 0 || len(data)%blockSize != 0 {
		return nil, errors.New("envelope: invalid padding")
	}
	padLen := int(data[len(data)-1])
	if padLen == 0 || padLen > blockSize {
		return nil, errors.New("envelope: invalid padding")
	}
	for _, b := range data[len(data)-padLen:] {
		if int(b) != padLen {
			return nil, errors.New("envelope: invalid padding")
		}
	}
	return data[:len(data)-padLen], nil
}
