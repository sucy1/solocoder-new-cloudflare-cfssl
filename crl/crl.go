// Package crl exposes Certificate Revocation List generation functionality
package crl

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"io"
	"math/big"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/cloudflare/cfssl/certdb"
	"github.com/cloudflare/cfssl/helpers"
	"github.com/cloudflare/cfssl/log"
)

var (
	oidAuthorityInfoAccess = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 1}
	oidOCSP                = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1}
)

type accessDescription struct {
	Method   asn1.ObjectIdentifier
	Location asn1.RawValue `asn1:"tag:6"`
}

type authorityInfoAccess []accessDescription

// NewCRLFromFile takes in a list of serial numbers, one per line, as well as the issuing certificate
// of the CRL, and the private key. This function is then used to parse the list and generate a CRL
func NewCRLFromFile(serialList, issuerFile, keyFile []byte, expiryTime string, ocspURL ...string) ([]byte, error) {

	var revokedCerts []pkix.RevokedCertificate
	var oneWeek = time.Duration(604800) * time.Second

	expiryInt, err := strconv.ParseInt(expiryTime, 0, 32)
	if err != nil {
		return nil, err
	}
	newDurationFromInt := time.Duration(expiryInt) * time.Second
	newExpiryTime := time.Now().Add(newDurationFromInt)
	if expiryInt == 0 {
		newExpiryTime = time.Now().Add(oneWeek)
	}

	// Parse the PEM encoded certificate
	issuerCert, err := helpers.ParseCertificatePEM(issuerFile)
	if err != nil {
		return nil, err
	}

	// Split input file by new lines
	individualCerts := strings.Split(string(serialList), "\n")

	// For every new line, create a new revokedCertificate and add it to slice
	for _, value := range individualCerts {
		if len(strings.TrimSpace(value)) == 0 {
			continue
		}

		tempBigInt := new(big.Int)
		tempBigInt.SetString(value, 10)
		tempCert := pkix.RevokedCertificate{
			SerialNumber:   tempBigInt,
			RevocationTime: time.Now(),
		}
		revokedCerts = append(revokedCerts, tempCert)
	}

	strPassword := os.Getenv("CFSSL_CA_PK_PASSWORD")
	password := []byte(strPassword)
	if strPassword == "" {
		password = nil
	}

	// Parse the key given
	key, err := helpers.ParsePrivateKeyPEMWithPassword(keyFile, password)
	if err != nil {
		log.Debugf("Malformed private key %v", err)
		return nil, err
	}

	var ocsp string
	if len(ocspURL) > 0 {
		ocsp = ocspURL[0]
	}
	return CreateGenericCRL(revokedCerts, key, issuerCert, newExpiryTime, ocsp)
}

// NewCRLFromDB takes in a list of CertificateRecords, as well as the issuing certificate
// of the CRL, and the private key. This function is then used to parse the records and generate a CRL
func NewCRLFromDB(certs []certdb.CertificateRecord, issuerCert *x509.Certificate, key crypto.Signer, expiryTime time.Duration, ocspURL ...string) ([]byte, error) {
	var revokedCerts []pkix.RevokedCertificate

	newExpiryTime := time.Now().Add(expiryTime)

	// For every record, create a new revokedCertificate and add it to slice
	for _, certRecord := range certs {
		serialInt := new(big.Int)
		serialInt.SetString(certRecord.Serial, 10)
		tempCert := pkix.RevokedCertificate{
			SerialNumber:   serialInt,
			RevocationTime: certRecord.RevokedAt,
		}
		revokedCerts = append(revokedCerts, tempCert)
	}

	var ocsp string
	if len(ocspURL) > 0 {
		ocsp = ocspURL[0]
	}
	return CreateGenericCRL(revokedCerts, key, issuerCert, newExpiryTime, ocsp)
}

func buildOCSPExtension(ocspURL string) (*pkix.Extension, error) {
	if ocspURL == "" {
		return nil, nil
	}

	aia := authorityInfoAccess{
		{
			Method: oidOCSP,
			Location: asn1.RawValue{
				Tag:   6,
				Class: 2,
				Bytes: []byte(ocspURL),
			},
		},
	}

	val, err := asn1.Marshal(aia)
	if err != nil {
		return nil, err
	}

	return &pkix.Extension{
		Id:    oidAuthorityInfoAccess,
		Value: val,
	}, nil
}

// CreateGenericCRL is a helper function that takes in all of the information above, and then calls the createCRL
// function. This outputs the bytes of the created CRL.
func CreateGenericCRL(certList []pkix.RevokedCertificate, key crypto.Signer, issuingCert *x509.Certificate, expiryTime time.Time, ocspURL ...string) ([]byte, error) {
	var extraExtensions []pkix.Extension

	if len(ocspURL) > 0 && ocspURL[0] != "" {
		ext, err := buildOCSPExtension(ocspURL[0])
		if err != nil {
			return nil, err
		}
		if ext != nil {
			extraExtensions = append(extraExtensions, *ext)
		}
	}

	crlBytes, err := CreateCRLWithExtensions(rand.Reader, issuingCert, key, certList, time.Now(), expiryTime, extraExtensions)
	if err != nil {
		log.Debugf("error creating CRL: %s", err)
	}

	return crlBytes, err
}

type tbsCertList struct {
	Version                 int `asn1:"optional,default:0"`
	Signature               pkix.AlgorithmIdentifier
	Issuer                  asn1.RawValue
	ThisUpdate              time.Time
	NextUpdate              time.Time `asn1:"optional"`
	RevokedCertificates     []pkix.RevokedCertificate `asn1:"optional"`
	Extensions              []pkix.Extension          `asn1:"optional,tag:0"`
}

type certificateList struct {
	TBSCertList        tbsCertList
	SignatureAlgorithm pkix.AlgorithmIdentifier
	SignatureValue     asn1.BitString
}

// CreateCRLWithExtensions creates a CRL with additional extensions.
func CreateCRLWithExtensions(randReader io.Reader, issuer *x509.Certificate, priv crypto.Signer, revokedCerts []pkix.RevokedCertificate, thisUpdate, nextUpdate time.Time, extraExtensions []pkix.Extension) ([]byte, error) {
	_ = &rsa.PublicKey{}
	_ = &ecdsa.PublicKey{}
	hashFunc := crypto.SHA256
	switch pub := issuer.PublicKey.(type) {
	case *rsa.PublicKey:
	case *ecdsa.PublicKey:
	default:
		_ = pub
	}

	issuerRDN := pkix.RDNSequence{}
	rest, err := asn1.Unmarshal(issuer.RawSubject, &issuerRDN)
	if err != nil {
		return nil, err
	}
	if len(rest) > 0 {
		return nil, x509.CertificateInvalidError{Cert: issuer, Reason: x509.NotAuthorizedToSign}
	}
	issuerRaw, err := asn1.Marshal(issuerRDN)
	if err != nil {
		return nil, err
	}

	sigAlgo := issuer.SignatureAlgorithm
	encodedSigAlgo, err := signatureAlgorithmFromX509(sigAlgo)
	if err != nil {
		return nil, err
	}

	_ = hashFunc

	tbsCertList := tbsCertList{
		Signature:           encodedSigAlgo,
		Issuer:              asn1.RawValue{FullBytes: issuerRaw},
		ThisUpdate:          thisUpdate,
		NextUpdate:          nextUpdate,
		RevokedCertificates: revokedCerts,
		Extensions:          extraExtensions,
	}

	tbsCertListContents, err := asn1.Marshal(tbsCertList)
	if err != nil {
		return nil, err
	}

	signature, err := priv.Sign(randReader, tbsCertListContents, getHash(sigAlgo))
	if err != nil {
		return nil, err
	}

	return asn1.Marshal(certificateList{
		TBSCertList:        tbsCertList,
		SignatureAlgorithm: encodedSigAlgo,
		SignatureValue:     asn1.BitString{Bytes: signature, BitLength: len(signature) * 8},
	})
}

func signatureAlgorithmFromX509(algo x509.SignatureAlgorithm) (pkix.AlgorithmIdentifier, error) {
	var oid asn1.ObjectIdentifier
	switch algo {
	case x509.SHA256WithRSA:
		oid = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
	case x509.SHA384WithRSA:
		oid = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 12}
	case x509.SHA512WithRSA:
		oid = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 13}
	case x509.ECDSAWithSHA256:
		oid = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	case x509.ECDSAWithSHA384:
		oid = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}
	case x509.ECDSAWithSHA512:
		oid = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 4}
	case x509.SHA1WithRSA:
		oid = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 5}
	default:
		return pkix.AlgorithmIdentifier{}, x509.ErrUnsupportedAlgorithm
	}
	return pkix.AlgorithmIdentifier{Algorithm: oid}, nil
}

func getHash(algo x509.SignatureAlgorithm) crypto.Hash {
	switch algo {
	case x509.SHA256WithRSA, x509.ECDSAWithSHA256:
		return crypto.SHA256
	case x509.SHA384WithRSA, x509.ECDSAWithSHA384:
		return crypto.SHA384
	case x509.SHA512WithRSA, x509.ECDSAWithSHA512:
		return crypto.SHA512
	default:
		return crypto.SHA1
	}
}
