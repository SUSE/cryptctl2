// cryptctl2 - Copyright (c) 2023 SUSE Software Solutions Germany GmbH, Germany
// This source code is licensed under GPL version 3 that can be found in LICENSE file.
package command

import (
	"cryptctl2/keyserv"
	"cryptctl2/routine"
	"cryptctl2/sys"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"time"
)

// Server - complete the initial setup.
func InitKeyServer() error {
	sys.LockMem()
	sysconf, err := sys.ParseSysconfigFile(SERVER_CONFIG_PATH, true)
	if err != nil {
		return fmt.Errorf("InitKeyServer: failed to read %s - %v", SERVER_CONFIG_PATH, err)
	}

	// Some of the mandatory questions will accept empty answers if a configuration already exists
	var reconfigure bool
	if sysconf.GetString(keyserv.SRV_CONF_PASS_HASH, "") != "" {
		reconfigure = true
		if !sys.InputBool(false, `You appear to have already initialised the configuration on this key server.
Would you like to re-configure it?`) {
			fmt.Println("OK, existing configuration is left untouched.")
			return nil
		}
	}
	fmt.Println("Please enter value for the following parameters, or leave blank to accept the default value.")

	// Ask for a new password and store its hash
	var pwd string
	pwdHint := ""
	if reconfigure {
		pwdHint = "*****"
	}
	for {
		pwd = sys.InputPassword(!reconfigure, pwdHint, "Access password (min. %d chars, no echo)", MIN_PASSWORD_LEN)
		if len(pwd) != 0 && len(pwd) < MIN_PASSWORD_LEN {
			fmt.Printf("\nPassword is too short, please enter a minimum of %d characters.\n", MIN_PASSWORD_LEN)
			continue
		}
		fmt.Println()
		confirmPwd := sys.InputPassword(!reconfigure, pwdHint, "Confirm access password (no echo)")
		fmt.Println()
		if confirmPwd == pwd {
			break
		} else {
			fmt.Println("Password does not match.")
			continue
		}
	}
	if pwd != "" {
		newSalt := keyserv.NewSalt()
		sysconf.Set(keyserv.SRV_CONF_PASS_SALT, hex.EncodeToString(newSalt[:]))
		newPwd := keyserv.HashPassword(newSalt, pwd)
		sysconf.Set(keyserv.SRV_CONF_PASS_HASH, hex.EncodeToString(newPwd[:]))
	}
	// Ask for TLS certificate and key, or generate a self-signed one if user wishes to.
	generateCert := false
	if reconfigure {
		// Server was previously initialised
		if tlsCert := sys.InputAbsFilePath(false,
			sysconf.GetString(keyserv.SRV_CONF_TLS_CERT, ""),
			"PEM-encoded TLS certificate or a certificate chain file"); tlsCert != "" {
			sysconf.Set(keyserv.SRV_CONF_TLS_CERT, tlsCert)
		}
	} else {
		// Propose to generate a self-signed certificate
		if tlsCert := sys.InputAbsFilePath(false, "", `PEM-encoded TLS certificate or a certificate chain file
(leave blank to auto-generate self-signed certificate)`); tlsCert == "" {
			generateCert = true
		} else {
			sysconf.Set(keyserv.SRV_CONF_TLS_CERT, tlsCert)
		}
	}
	if generateCert {
		certDir := sysconf.GetString(keyserv.SRV_CONF_CERT_DIR, "/var/lib/cryptctl2/certs")
		if certDir = sys.InputAbsFilePath(true, certDir,
			"Certificat directory"); certDir != "" {
			sysconf.Set(keyserv.SRV_CONF_CERT_DIR, certDir)
		}
		certCommonName, hostIP := sys.GetHostnameAndIP()
		certCommonName = sys.Input(true, certCommonName, "Host name for the generated certificate:")
		hostIP = sys.Input(false, hostIP, "IP address for the generated certificate:")

		if err := os.MkdirAll(certDir, 0700); err != nil {
			return fmt.Errorf("Failed to create directory \"%s\" for storing generated certificates - %v", certDir, err)
		}
		maxAge := sys.InputInt(true, 10, 1, 100, "How long should the certificate be valid? Value in years.")
		organization := sys.Input(true, "", "Enter the name of your organisation. This will be included into the certificat.")
		// While openssl generates the certificate, print dots to stdout to show that program is busy.
		fmt.Println("Generating certificate...")
		opensslDone := make(chan bool, 1)
		go func() {
			for {
				select {
				case <-opensslDone:
					return
				case <-time.After(1 * time.Second):
					fmt.Print(".")
					os.Stdout.Sync()
				}
			}
		}()
		err := routine.GenerateSelfSignedCaCert(certCommonName, hostIP, certDir, organization, maxAge)
		opensslDone <- true
		if err != nil {
			return err
		}
		fmt.Printf("\nSelf-signed CA and a certificate has been generated for host name '%s' in '%s'.\n", certCommonName, certDir)
		// Point sysconfig values to the generated certificate
		sysconf.Set(keyserv.SRV_CONF_TLS_CERT, path.Join(certDir, certCommonName+".crt"))
		sysconf.Set(keyserv.SRV_CONF_TLS_KEY, path.Join(certDir, certCommonName+".key"))
	} else {
		// If certificate was specified, ask for its key file
		if tlsKey := sys.InputAbsFilePath(!reconfigure,
			sysconf.GetString(keyserv.SRV_CONF_TLS_KEY, ""),
			"PEM-encoded TLS certificate key that corresponds to the certificate"); tlsKey != "" {
			sysconf.Set(keyserv.SRV_CONF_TLS_KEY, tlsKey)
		}
	}

	// Walk through the remaining mandatory configuration keys
	if listenAddr := sys.Input(false,
		sysconf.GetString(keyserv.SRV_CONF_LISTEN_ADDR, "0.0.0.0"),
		"IP address for the server to listen on (0.0.0.0 to listen on all network interfaces)"); listenAddr != "" {
		sysconf.Set(keyserv.SRV_CONF_LISTEN_ADDR, listenAddr)
	}
	if listenPort := sys.InputInt(false,
		sysconf.GetInt(keyserv.SRV_CONF_LISTEN_PORT, 3737), 1, 65535,
		"TCP port number to listen on"); listenPort != 0 {
		sysconf.Set(keyserv.SRV_CONF_LISTEN_PORT, listenPort)
	}
	if keyDBDir := sys.InputAbsFilePath(true,
		sysconf.GetString(keyserv.SRV_CONF_KEYDB_DIR, "/var/lib/cryptctl2/keydb"),
		"Key database directory"); keyDBDir != "" {
		sysconf.Set(keyserv.SRV_CONF_KEYDB_DIR, keyDBDir)
	}
	// Walk through client certificate verification settings
	validateClient := sys.InputBool(sysconf.GetString(keyserv.SRV_CONF_TLS_CA, "") != "",
		"Should clients present their certificate in order to access this server?")
	sysconf.Set(keyserv.SRV_CONF_TLS_VALIDATE_CLIENT, validateClient)
	if validateClient {
		sysconf.Set(keyserv.SRV_CONF_TLS_CA,
			sys.InputAbsFilePath(true,
				sysconf.GetString(keyserv.SRV_CONF_TLS_CA, ""),
				"PEM-encoded TLS certificate authority that will issue client certificates"))
	}
	// Walk through KMIP settings
	useExternalKMIPServer := sys.InputBool(sysconf.GetString(keyserv.SRV_CONF_KMIP_SERVER_ADDRS, "") != "",
		"Should encryption keys be kept on a KMIP-compatible key management appliance?")
	if useExternalKMIPServer {
		sysconf.Set(keyserv.SRV_CONF_KMIP_SERVER_ADDRS, sys.Input(true, "", "Space-separated KMIP server addresses (host1:port1 host2:port2 ...)"))
		sysconf.Set(keyserv.SRV_CONF_KMIP_SERVER_USER, sys.Input(false, "", "KMIP username"))
		sysconf.Set(keyserv.SRV_CONF_KMIP_SERVER_PASS, sys.InputPassword(false, "", "KMIP password"))
		sysconf.Set(keyserv.SRV_CONF_KMIP_SERVER_TLS_CA, sys.InputAbsFilePath(false, "", "PEM-encoded TLS certificate authority of KMIP server"))
		sysconf.Set(keyserv.SRV_CONF_KMIP_SERVER_TLS_CERT, sys.InputAbsFilePath(false, "", "PEM-encoded TLS client identity certificate"))
		sysconf.Set(keyserv.SRV_CONF_KMIP_SERVER_TLS_KEY, sys.InputAbsFilePath(false, "", "PEM-encoded TLS client identity certificate key"))
	}
	// Walk through optional email settings
	fmt.Println("\nTo enable Email notifications, enter the following parameters:")
	if mta := sys.Input(false,
		sysconf.GetString(keyserv.SRV_CONF_MAIL_AGENT_AND_PORT, ""),
		"SMTP server name (not IP address) and port such as \"example.com:25\""); mta != "" {
		sysconf.Set(keyserv.SRV_CONF_MAIL_AGENT_AND_PORT, mta)
	}
	if sysconf.GetString(keyserv.SRV_CONF_MAIL_AGENT_AND_PORT, "") != "" {
		if username := sys.Input(false,
			sysconf.GetString(keyserv.SRV_CONF_MAIL_AGENT_USERNAME, ""),
			"Plain authentication username for access to mail agent (optional)"); username != "" {
			sysconf.Set(keyserv.SRV_CONF_MAIL_AGENT_USERNAME, username)
			if password := sys.Input(false,
				sysconf.GetString(keyserv.SRV_CONF_MAIL_AGENT_PASSWORD, ""),
				"Plain authentication password for access to mail agent (optional)"); password != "" {
				sysconf.Set(keyserv.SRV_CONF_MAIL_AGENT_PASSWORD, password)
			}
		}
		if fromAddr := sys.Input(false,
			sysconf.GetString(keyserv.SRV_CONF_MAIL_FROM_ADDR, ""),
			"Notification email's FROM address such as \"root@example.com\""); fromAddr != "" {
			sysconf.Set(keyserv.SRV_CONF_MAIL_FROM_ADDR, fromAddr)
		}
		if recipients := sys.Input(false,
			sysconf.GetString(keyserv.SRV_CONF_MAIL_RECIPIENTS, ""),
			"Space-separated notification recipients such as \"admin@example.com\""); recipients != "" {
			sysconf.Set(keyserv.SRV_CONF_MAIL_RECIPIENTS, recipients)
		}
		if creationSubj := sys.Input(false,
			"",
			"Subject of key-creation notification email"); creationSubj != "" {
			sysconf.Set(keyserv.SRV_CONF_MAIL_CREATION_SUBJ, creationSubj)
		}
		if creationText := sys.Input(false,
			"",
			"Text of key-creation notification email"); creationText != "" {
			sysconf.Set(keyserv.SRV_CONF_MAIL_CREATION_TEXT, creationText)
		}
		if retrievalSubj := sys.Input(false,
			"",
			"Subject of key-retrieval notification email"); retrievalSubj != "" {
			sysconf.Set(keyserv.SRV_CONF_MAIL_RETRIEVAL_SUBJ, retrievalSubj)
		}
		if retrievalText := sys.Input(false,
			"",
			"Text of key-retrieval notification email"); retrievalText != "" {
			sysconf.Set(keyserv.SRV_CONF_MAIL_RETRIEVAL_TEXT, retrievalText)
		}
	}
	if err := ioutil.WriteFile(SERVER_CONFIG_PATH, []byte(sysconf.ToText()), 0600); err != nil {
		return fmt.Errorf("Failed to save settings into %s - %v", SERVER_CONFIG_PATH, err)
	}
	// Restart server
	fmt.Println("\nSettings have been saved successfully!")
	var start bool
	if sys.SystemctlIsRunning(SERVER_DAEMON) {
		start = sys.InputBool(true, "Would you like to restart key server (%s) to apply the new settings?", SERVER_DAEMON)
	} else {
		start = sys.InputBool(true, "Would you like to start key server (%s) now?", SERVER_DAEMON)
	}
	if !start {
		return nil
	}
	// (Re)start server and then display the PID in output.
	if err := sys.SystemctlEnableRestart(SERVER_DAEMON); err != nil {
		return fmt.Errorf("%v", err)
	}
	// Wait up to 5 seconds for server daemon to start
	for i := 0; i < 5; i++ {
		if pid := sys.SystemctlGetMainPID(SERVER_DAEMON); pid != 0 {
			// After server appears to be running, monitor it for 3 more seconds to make sure it stays running.
			for j := 0; j < 3; j++ {
				if pid := sys.SystemctlGetMainPID(SERVER_DAEMON); pid == 0 {
					// Server went down after it had started
					return fmt.Errorf("Startup failed. Please inspect the output of \"systemctl status %s\".\n", SERVER_DAEMON)
				}
				time.Sleep(1 * time.Second)
			}
			fmt.Printf("Key server is now running (PID %d).\n", pid)
			return nil
		}
		time.Sleep(1 * time.Second)
	}
	// Server failed to start in time
	fmt.Printf("Startup failed. Please inspect the output of \"systemctl status %s\".\n", SERVER_DAEMON)
	return nil
}

func CreateCertificate(DNSName, IPAddress string) error {

	sysconf, err := sys.ParseSysconfigFile(SERVER_CONFIG_PATH, true)
	if err != nil {
		return fmt.Errorf("InitKeyServer: failed to read %s - %v", SERVER_CONFIG_PATH, err)
	}
	certDir := sysconf.GetString(keyserv.SRV_CONF_CERT_DIR, "/var/lib/cryptctl2/certs")
	if err := routine.GenerateCertificate(DNSName, IPAddress, certDir); err != nil {
		return fmt.Errorf("Failed to create certificate %s - %v", DNSName, err)
	}
	return nil
}
