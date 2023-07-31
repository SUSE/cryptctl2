// cryptctl2 - Copyright (c) 2023 SUSE Software Solutions Germany GmbH, Germany
// This source code is licensed under GPL version 3 that can be found in LICENSE file.
package routine

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path"
	"strconv"
	"syscall"
	"time"
)

// Reads the actual serial number increments it and saves the new value.
func GetNextSerial(certDir string) (int64, error) {
	serialPath := path.Join(certDir, "serial")
	data := make([]byte, 100)
	file, err := os.OpenFile(serialPath, os.O_RDWR, 0600)
	if err != nil {
		return 0, err
	}
	defer file.Close()
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX); err != nil {
		return 0, err
	}
	len, err := file.Read(data)
	if err != nil {
		return 0, err
	}
	if serial, err := strconv.ParseInt(string(data[:len]), 10, 64); err != nil {
		return 0, err
	} else {
		serial++
		file.Seek(0, 0)
		if _, err := file.Write([]byte(strconv.FormatInt(serial, 10))); err != nil {
			return 0, err
		}
		return serial, nil
	}
}

func GenerateSelfSignedCaCert(commonName, ipAddress, certDir, organization string, maxAge int) error {
	caCertFilePath := path.Join(certDir, "ca.crt")
	caKeyFilePath := path.Join(certDir, "ca.key")

	if err := os.WriteFile(path.Join(certDir, "serial"), []byte("1"), 0600); err != nil {
		return err
	}
	// set up our CA certificate
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{organization},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(maxAge, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	caPEM := new(bytes.Buffer)
	caPrivKeyPEM := new(bytes.Buffer)

	// create ca private and public key
	caPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return err
	}
	caBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, &caPrivKey.PublicKey, caPrivKey)
	if err != nil {
		return err
	}
	// pem encode
	pem.Encode(caPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caBytes,
	})

	pem.Encode(caPrivKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(caPrivKey),
	})

	if err = os.WriteFile(caCertFilePath, caPEM.Bytes(), 0400); err != nil {
		return err
	}
	if err = os.WriteFile(caKeyFilePath, caPrivKeyPEM.Bytes(), 0400); err != nil {
		return err
	}
	return GenerateCertificate(commonName, ipAddress, certDir)
}

func LoadCA(certDir string) (*x509.Certificate, *rsa.PrivateKey) {

	caCertFilePath := path.Join(certDir, "ca.crt")
	caKeyFilePath := path.Join(certDir, "ca.key")
	cf, e := os.ReadFile(caCertFilePath)
	if e != nil {
		fmt.Println("cfload:", e.Error())
		os.Exit(1)
	}

	kf, e := os.ReadFile(caKeyFilePath)
	if e != nil {
		fmt.Println("kfload:", e.Error())
		os.Exit(1)
	}
	cpb, cr := pem.Decode(cf)
	fmt.Println(string(cr))
	kpb, kr := pem.Decode(kf)
	fmt.Println(string(kr))
	crt, e := x509.ParseCertificate(cpb.Bytes)

	if e != nil {
		fmt.Println("parsex509:", e.Error())
		os.Exit(1)
	}
	key, e := x509.ParsePKCS1PrivateKey(kpb.Bytes)
	if e != nil {
		fmt.Println("parsekey:", e.Error())
		os.Exit(1)
	}
	return crt, key
}

func GenerateCertificate(dnsName, ipAdress, certDir string) error {
	caCert, caPrivKey := LoadCA(certDir)
	certPEM := new(bytes.Buffer)
	certPrivKeyPEM := new(bytes.Buffer)
	certFilePath := path.Join(certDir, dnsName+".crt")
	keyFilePath := path.Join(certDir, dnsName+".key")
	serial, err := GetNextSerial(certDir)
	if err != nil {
		fmt.Println("Can not get new serial:", err.Error())
		os.Exit(1)
	}
	// set up our server certificate
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject: pkix.Name{
			CommonName:   dnsName,
			Organization: caCert.Subject.Organization,
		},
		NotBefore:    time.Now(),
		NotAfter:     caCert.NotAfter,
		SubjectKeyId: []byte{1, 2, 3, 4, 6},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		DNSNames:     []string{dnsName},
	}
	if ip := net.ParseIP(ipAdress); ip != nil {
		cert.IPAddresses = []net.IP{ip}
	}
	certPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return err
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, cert, caCert, &certPrivKey.PublicKey, caPrivKey)
	if err != nil {
		return err
	}

	pem.Encode(certPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})

	pem.Encode(certPrivKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(certPrivKey),
	})
	if err = os.WriteFile(certFilePath, certPEM.Bytes(), 0400); err != nil {
		return err
	}
	if err = os.WriteFile(keyFilePath, certPrivKeyPEM.Bytes(), 0400); err != nil {
		return err
	}

	return nil
}
