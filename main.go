//go:build linux
// +build linux

// cryptctl2 - Copyright (c) 2023 SUSE Software Solutions Germany GmbH, Germany
// This source code is licensed under GPL version 3 that can be found in LICENSE file.
package main

import (
	"cryptctl2/command"
	"cryptctl2/sys"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
)

var helpText = `cryptctl2: encrypt and decrypt file systems using network key server.
Copyright (C) 2023 SUSE Software Solutions Germany GmbH, Germany
This program comes with ABSOLUTELY NO WARRANTY. This is free software, and you
are welcome to redistribute it under certain conditions; see file "LICENSE".

Syntax: cryptctl2 -action <action> [options]

Server actions:
daemon
	Start the cryptctl2 server daemon.
init-server
	Set up this computer as a new key server.
list-keys
	Show all encryption keys.
show-key -deviceID=UUID
	Display pending-commands and details of a key.
edit-key -deviceID=UUID
	Edit stored key information.
send-command
	Record a pending mount/umount command for a disk.
clear-commands
	Clear all pending commands of a disk.
add-allowed-client -deviceID=String -allowedClient=String
	Allow a client to access a device.
remove-allowed-client -disk=String -allowedClient=String
	Remove client from the access list of a device.
list-allowed-clients -disk=String
	List the clients which has access to a device.
create-client-certificate -dnsName=String [-ipAdress=String]
	Creates a client certificate for the given DNS-Name and if given IP-Address

Client actions:
client-daemon
	Start the cryptctl2 client daemon.
encrypt
	Set up a new file system for encryption.
inplace-encrypt
	Set up an existing file system for encryption.
auto-unlock -deviceID=UUID
	Paswordless unlock a registered device.
check-auto-unlock -deviceID=UUID
	Check if a passwordless unlock is possible on this client.
online-unlock
	Forcibly unlock all file systems via key server.
offline-unlock
	Unlock a file system via a key record file.

Actions on both server and client:
add-device -deviceID=String -mappedName=String [-mountPoint=String -mountOptions=String -maxActive=Int -allowedClients=String -autoEncyption=Bool]
	Creates a new device in the keydb.
`

func PrintHelpAndExit(exitStatus int) {
	fmt.Println(helpText)
	flag.PrintDefaults()
	os.Exit(exitStatus)
}

func main() {
	// Print stack trace of all goroutines on SIGQUIT for debugging
	osSignal := make(chan os.Signal, 1)
	signal.Notify(osSignal, syscall.SIGQUIT)
	go func() {
		for {
			<-osSignal
			outBuf := make([]byte, 2048)
			for {
				// Keep re-collecting stack traces until the buffer is large enough to hold all of them
				sizeWritten := runtime.Stack(outBuf, false)
				if len(outBuf) >= sizeWritten {
					fmt.Fprint(os.Stderr, string(outBuf))
					break
				}
				outBuf = make([]byte, 2*len(outBuf))
			}
		}
	}()

	action := flag.String("action", "daemon", helpText)
	deviceID := flag.String("deviceID", "", "The id of the device. In normal case this is the partition UUID. Ohterwise the type of the used ID need to be added as prefix separated by '='. Ex.: SERIAL:3600140585b053f0034b46ccbe409913b")
	mappedName := flag.String("mappedName", "", "The mapped name of the device.")
	mountPoint := flag.String("mountPoint", "", "The path where the device need to be mounted if any.")
	mountOptions := flag.String("mountOptions", "", "Comma separated list of mount options.")
	//maxAlive := flag.Int("maxAlive",3600,"How long (in seconds) should be stay the device encripted if the cryptcl server is not accessible.")
	maxActive := flag.Int("maxActive", 0, "How many clients may encrypt the device to same time.")
	allowedClients := flag.String("allowedClients", "", "Comma separated list of client which may have acces to the device.")
	autoEncryption := flag.Bool("autoEncryption", false, "Should the device autmaticaly encrypted if it will be accessed at first time?")
	fileSystem := flag.String("fileSystem", "", "File system to be created if auto encryption is turned on.")
	dnsName := flag.String("dnsName", "", "DNS-Name of the client.")
	ipAddress := flag.String("ipAddress", "", "IPAddress of the client.")
	flag.Parse()
	switch *action {
	case "help":
		PrintHelpAndExit(0)
	case "daemon":
		// Server - run key service daemon
		if err := command.KeyRPCDaemon(); err != nil {
			sys.ErrorExit("%v", err)
		}
	case "init-server":
		// Server - complete the initial setup
		if err := command.InitKeyServer(); err != nil {
			sys.ErrorExit("%v", err)
		}
	case "list-keys":
		// Server - print all key records sorted according to last access
		if err := command.ListKeys(); err != nil {
			sys.ErrorExit("%v", err)
		}
	case "edit-key":
		// Server - let user edit key details such as mount point and mount options
		if *deviceID == "" {
			sys.ErrorExit("Please specify -deviceID of the key that you wish to edit.")
		}
		if err := command.EditKey(*deviceID); err != nil {
			sys.ErrorExit("%v", err)
		}
	case "show-key":
		// Server - show key record details except key content
		if *deviceID == "" {
			sys.ErrorExit("Please specify -deviceID of the key that you wish to see.")
		}
		if err := command.ShowKey(*deviceID); err != nil {
			sys.ErrorExit("%v", err)
		}
	case "send-command":
		if err := command.SendCommand(); err != nil {
			sys.ErrorExit("%v", err)
		}
	case "clear-commands":
		if err := command.ClearPendingCommands(); err != nil {
			sys.ErrorExit("%v", err)
		}
	case "add-device":
		if *deviceID == "" {
			sys.ErrorExit("Please specify atlast -deviceID of the device.")
		}
		if err := command.AddDevice(*deviceID, *mappedName, *mountPoint, *mountOptions, *allowedClients, *maxActive, *autoEncryption, *fileSystem); err != nil {
			sys.ErrorExit("%v", err)
		}
	case "add-allowed-client":
		if *deviceID == "" && *allowedClients == "" {
			sys.ErrorExit("Please specify -deviceID of the disk and the concerned DNS Name(s).")
		}
		for _, client := range strings.Split(*allowedClients, ",") {
			if err := command.AddAllowedClient(*deviceID, client); err != nil {
				sys.ErrorExit("%v", err)
			}
		}

	case "remove-allowed-client":
		if *deviceID == "" && *allowedClients == "" {
			sys.ErrorExit("Please specify -deviceID of the disk and the concerned DNS Name(s).")
		}
		for _, client := range strings.Split(*allowedClients, ",") {
			if err := command.AddAllowedClient(*deviceID, client); err != nil {
				sys.ErrorExit("%v", err)
			}
		}
	case "list-allowed-clients":
		if *deviceID == "" {
			sys.ErrorExit("Please specify following parameter: -deviceID")
		}
		if err := command.ListAllowedClient(*deviceID); err != nil {
			sys.ErrorExit("%v", err)
		}
	case "create-client-certificate":
		if *dnsName != "" {
			if err := command.CreateCertificate(*dnsName, *ipAddress); err != nil {
				sys.ErrorExit("%v", err)
			}
		} else {
			sys.ErrorExit("Please specify following parameter: -dnsName [-ipAddress]")
		}
	// Client functions
	case "client-daemon":
		// Client - run daemon that primarily polls and reacts to pending commands issued by RPC server
		if err := command.ClientDaemon(); err != nil {
			sys.ErrorExit("%v", err)
		}
	case "encrypt":
		// Client - set up a new encrypted disk
		if err := command.EncryptFS(); err != nil {
			sys.ErrorExit("%v", err)
		}
	case "auto-unlock":
		// Client - automatically unlock a file system without using a password
		if *deviceID == "" {
			sys.ErrorExit("Please specify following parameter: -deviceID")
		}
		if err := command.AutoOnlineUnlockFS(*deviceID); err != nil {
			sys.ErrorExit("%v", err)
		}
	case "check-auto-unlock":
		// Client - automatically unlock a file system without using a password
		if *deviceID == "" {
			sys.ErrorExit("Please specify following parameter: -deviceID")
		}
		if err := command.CheckAutoUnlock(*deviceID); err != nil {
			sys.ErrorExit("%v", err)
		}
	case "online-unlock":
		// Client - manually unlock all file systems using a key server and password
		if err := command.ManOnlineUnlockFS(); err != nil {
			sys.ErrorExit("%v", err)
		}
	case "offline-unlock":
		// Client - manually unlock a single file system using a key record file
		if err := command.ManOfflineUnlockFS(); err != nil {
			sys.ErrorExit("%v", err)
		}
	case "erase":
		// Client - erase encryption headers for the encrypted disk
		if err := command.EraseKey(); err != nil {
			sys.ErrorExit("%v", err)
		}
	default:
		PrintHelpAndExit(1)
	}
}
