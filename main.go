//go:build linux
// +build linux

// cryptctl2 - Copyright (c) 2023 SUSE Software Solutions Germany GmbH, Germany
// This source code is licensed under GPL version 3 that can be found in LICENSE file.
package main

import (
	"cryptctl2/command"
	"cryptctl2/sys"
	"fmt"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"syscall"
)

func PrintHelpAndExit(exitStatus int) {
	fmt.Println(`cryptctl2: encrypt and decrypt file systems using network key server.
Copyright (C) 2023 SUSE Software Solutions Germany GmbH, Germany
This program comes with ABSOLUTELY NO WARRANTY.This is free software, and you
are welcome to redistribute it under certain conditions; see file "LICENSE".

Maintain a key server:
  cryptctl2 init-server     Set up this computer as a new key server.
  cryptctl2 list-keys       Show all encryption keys.
  cryptctl2 show-key UUID   Display pending-commands and details of a key.
  cryptctl2 edit-key UUID   Edit stored key information.
  cryptctl2 send-command    Record a pending mount/umount command for a disk.
  cryptctl2 clear-commands  Clear all pending commands of a disk.
  cryptctl2 add-device UUID MappedName MountPoint MountOptions MaxActive AllowedClients AutoEncyption
                            Creates a new device in the keydb.
  cryptctl2 add-allowed-client UUID AllowedClient
                            Allow a client to access a device.
  cryptctl2 remove-allowed-client UUID AllowedClient
  							Remove client from the access list of a device.
  cryptctl2 list-allowed-clients UUID
  							List the clients which has access to a device.
  cryprctl2 create-client-certificate DNSName [IPAdress]

Encrypt/unlock file systems:
  cryptctl2 encrypt         Set up a new file system for encryption.
  cryptctl2 inplace-encrypt Set up an existing file system for encryption.
  cryptctl2 auto-unlock     Paswordless unlock a registered device.
  cryptctl2 online-unlock   Forcibly unlock all file systems via key server.
  cryptctl2 offline-unlock  Unlock a file system via a key record file.`)
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

	if len(os.Args) == 1 {
		PrintHelpAndExit(0)
	}

	switch os.Args[1] {
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
		if len(os.Args) < 3 {
			sys.ErrorExit("Please specify UUID of the key that you wish to edit.")
		}
		if err := command.EditKey(os.Args[2]); err != nil {
			sys.ErrorExit("%v", err)
		}
	case "show-key":
		// Server - show key record details except key content
		if len(os.Args) < 3 {
			sys.ErrorExit("Please specify UUID of the key that you wish to see.")
		}
		if err := command.ShowKey(os.Args[2]); err != nil {
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
		if len(os.Args) != 9 {
			sys.ErrorExit("Please specify following parameters: UUID MappedName MountPoint MountOptions MaxActive AllowedClients AutoEncyption")
		}
		if err := command.AddDevice(os.Args[2], os.Args[3], os.Args[4], os.Args[5], os.Args[6], os.Args[7], os.Args[8]); err != nil {
			sys.ErrorExit("%v", err)
		}
	case "add-allowed-client":
		if len(os.Args) != 4 {
			sys.ErrorExit("Please specify following parameters: UUID AllowedClient")
		}
		if err := command.AddAllowedClient(os.Args[2], os.Args[3]); err != nil {
			sys.ErrorExit("%v", err)
		}
	case "remove-allowed-client":
		if len(os.Args) != 4 {
			sys.ErrorExit("Please specify following parameters: UUID AllowedClient")
		}
		if err := command.AddAllowedClient(os.Args[2], os.Args[3]); err != nil {
			sys.ErrorExit("%v", err)
		}
	case "list-allowed-clients":
		if len(os.Args) != 3 {
			sys.ErrorExit("Please specify following parameter: UUID")
		}
		if err := command.ListAllowedClient(os.Args[2]); err != nil {
			sys.ErrorExit("%v", err)
		}
	case "create-client-certificate":
		if len(os.Args) == 3 {
			if err := command.CreateCertificate(os.Args[2], ""); err != nil {
				sys.ErrorExit("%v", err)
			}
		} else if len(os.Args) == 4 {
			if err := command.CreateCertificate(os.Args[2], os.Args[3]); err != nil {
				sys.ErrorExit("%v", err)
			}
		} else {
			sys.ErrorExit("Please specify following parameter: DNSName [IPAddress]")
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
		if len(os.Args) < 3 {
			sys.ErrorExit("UUID is missing from command line parameters")
		}
		if err := command.AutoOnlineUnlockFS(os.Args[2]); err != nil {
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
