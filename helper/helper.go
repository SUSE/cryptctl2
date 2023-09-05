// cryptctl2 - Copyright (c) 2023 SUSE Software Solutions Germany GmbH, Germany
// This source code is licensed under GPL version 3 that can be found in LICENSE file.
package helper

import (
	"crypto/tls"
)

/*
Function to check if any element of an array is the searched string
*/
func Contains(list []string, b string) bool {
	for _, s := range list {
		if s == b {
			return true
		}
	}
	return false
}

/*
Function to check if all elements of an array are empty
*/
func IsEmpty(list []string) bool {
	for _, s := range list {
		if s != "" {
			return false
		}
	}
	return true
}

/*
Delivers the DNSName and IPAddress from a tls certificate
Only the first element of both array are trated
*/
func GetCertificatInfo(conn *tls.Conn) (DNSName, IPAddress string) {
	state := conn.ConnectionState()
	for _, cert := range state.PeerCertificates {
		if len(cert.DNSNames) != 0 {
			DNSName = cert.DNSNames[0]
		}
		if len(cert.IPAddresses) != 0 {
			IPAddress = cert.IPAddresses[0].String()
		}
	}
	return
}
