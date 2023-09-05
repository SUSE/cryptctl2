// cryptctl2 - Copyright (c) 2023 SUSE Software Solutions Germany GmbH, Germany
// This source code is licensed under GPL version 3 that can be found in LICENSE file.
package command

import (
	"cryptctl2/helper"
	"cryptctl2/keydb"
	"cryptctl2/keyserv"
	"cryptctl2/routine"
	"cryptctl2/sys"
	"errors"
	"fmt"
	"log"
	"runtime"
	"strconv"
	"strings"
	"time"
)

const (
	SERVER_DAEMON      = "cryptctl2-server"
	SERVER_CONFIG_PATH = "/etc/sysconfig/cryptctl2-server"
	TIME_OUTPUT_FORMAT = "1967-04-17 23:04:00"
	MIN_PASSWORD_LEN   = 10

	PendingCommandMount  = "mount"  // PendingCommandMount is the content of a pending command that tells client computer to mount that disk.
	PendingCommandUmount = "umount" // PendingCommandUmount is the content of a pending command that tells client computer to umount that disk.
)

// Server - run key service daemon.
func KeyRPCDaemon() error {
	sys.LockMem()
	sysconf, err := sys.ParseSysconfigFile(SERVER_CONFIG_PATH, true)
	if err != nil {
		return fmt.Errorf("Failed to read configuratioon file \"%s\" - %v", SERVER_CONFIG_PATH, err)
	}
	srvConf := keyserv.CryptServiceConfig{}
	if err := srvConf.ReadFromSysconfig(sysconf); err != nil {
		return fmt.Errorf("Failed to load configuration from file \"%s\" - %v", SERVER_CONFIG_PATH, err)
	}
	mailer := keyserv.Mailer{}
	mailer.ReadFromSysconfig(sysconf)
	srv, err := keyserv.NewCryptServer(srvConf, mailer)
	if err != nil {
		return fmt.Errorf("Failed to initialise server - %v", err)
	}
	// Print helpful information regarding server's initial setup and mailer configuration
	if nonFatalErr := srv.CheckInitialSetup(); nonFatalErr != nil {
		log.Print("Key server is not confiured yet. Please run `cryptctl2 init-server` to complete initial setup.")
	}
	if nonFatalErr := mailer.ValidateConfig(); nonFatalErr == nil {
		log.Printf("Email notifications will be sent from %s to %v via %s",
			mailer.FromAddress, mailer.Recipients, mailer.AgentAddressPort)
	} else {
		log.Printf("Email notifications are not enabled: %v", nonFatalErr)
	}
	log.Printf("GOMAXPROCS is currently: %d", runtime.GOMAXPROCS(-1))
	// Start two RPC servers, one on TCP and the other on Unix domain socket.
	if err := srv.ListenTCP(); err != nil {
		return fmt.Errorf("KeyRPCDaemon: failed to listen for TCP connections - %v", err)
	}
	if err := srv.ListenUnix(); err != nil {
		return fmt.Errorf("KeyRPCDaemon: failed to listen for domain socket connections - %v", err)
	}
	go srv.HandleUnixConnections()
	srv.HandleTCPConnections() // intentionally block here
	return nil
}

/*
Open key database from the location specified in sysconfig file.
If UUID is given, the database will only load a single record.
*/
func OpenKeyDB(recordUUID string) (*keydb.DB, error) {
	sys.LockMem()
	sysconf, err := sys.ParseSysconfigFile(SERVER_CONFIG_PATH, true)
	if err != nil {
		return nil, fmt.Errorf("OpenKeyDB: failed to determine database path from configuration file \"%s\" - %v", SERVER_CONFIG_PATH, err)
	}
	dbDir := sysconf.GetString(keyserv.SRV_CONF_KEYDB_DIR, "")
	if dbDir == "" {
		return nil, errors.New("Key database directory is not configured. Is the server initialised?")
	}
	var db *keydb.DB
	if recordUUID == "" {
		// Load entire directory of database records into memory
		db, err = keydb.OpenDB(dbDir)
		if err != nil {
			return nil, fmt.Errorf("OpenKeyDB: failed to open database directory \"%s\" - %v", dbDir, err)
		}
	} else {
		// Load only one record into memory
		db, err = keydb.OpenDBOneRecord(dbDir, recordUUID)
		if err != nil {
			return nil, fmt.Errorf("OpenKeyDB: failed to open record \"%s\" - %v", recordUUID, err)
		}
	}
	return db, nil
}

// Server - print all key records sorted according to last access.
func ListKeys() error {
	sys.LockMem()
	db, err := OpenKeyDB("")
	if err != nil {
		return err
	}
	recList := db.List()
	fmt.Printf("Total: %d records (date and time are in zone %s)\n", len(recList), time.Now().Format("MST"))
	// Print mount point last, making output possible to be parsed by a program
	fmt.Println("Used By         When                ID           UUID                                 Max.Client Allowed.Client Act.Client Mount.Point    ")
	for _, rec := range recList {
		outputTime := time.Unix(rec.LastRetrieval.Timestamp, 0).Format(TIME_OUTPUT_FORMAT)
		rec.RemoveDeadHosts()
		fmt.Printf("%-15s %-19s %-12s %-36s %-10s %-14s %-11s %-15s %s\n",
			rec.LastRetrieval.IP,
			outputTime,
			rec.ID, rec.UUID,
			strconv.Itoa(rec.MaxActive),
			strconv.Itoa(len(rec.AllowedClients)),
			strconv.Itoa(len(rec.AliveMessages)),
			rec.MountPoint,
			strconv.Itoa(len(rec.Key)),
		)
	}
	return nil
}

func UpdateRecord(db *keydb.DB, rec keydb.Record) error {
	// Write record file and restart server to let it reload all records into memory
	if _, err := db.Upsert(rec); err != nil {
		return fmt.Errorf("Failed to update database record - %v", err)
	}
	fmt.Println("Record has been updated successfully.")
	if sys.SystemctlIsRunning(SERVER_DAEMON) {
		fmt.Println("Restarting key server...")
		if err := sys.SystemctlEnableRestart(SERVER_DAEMON); err != nil {
			return err
		}
		fmt.Println("All done.")
	}
	return nil
}

func AddAllowedClient(uuid, newClient string) error {
	sys.LockMem()
	db, err := OpenKeyDB(uuid)
	if err != nil {
		return err
	}
	rec, found := db.GetByUUID(uuid)
	if !found {
		return fmt.Errorf("Cannot find record for UUID %s", uuid)
	}
	if !helper.Contains(rec.AllowedClients, newClient) {
		rec.AllowedClients = append(rec.AllowedClients, newClient)
		return UpdateRecord(db, rec)
	}
	fmt.Println("Nothing to do. Client already contained")
	return nil
}

func DeleteAllowedClient(uuid, client string) error {
	sys.LockMem()
	db, err := OpenKeyDB(uuid)
	if err != nil {
		return err
	}
	rec, found := db.GetByUUID(uuid)
	if !found {
		return fmt.Errorf("Cannot find record for UUID %s", uuid)
	}
	if helper.Contains(rec.AllowedClients, client) {
		a := []string{}
		for _, s := range rec.AllowedClients {
			if s != client {
				a = append(a, s)
			}
		}
		rec.AllowedClients = a
		return UpdateRecord(db, rec)
	}
	fmt.Println("Nothing to do. Client not contained")
	return nil
}

func ListAllowedClient(uuid string) error {
	sys.LockMem()
	db, err := OpenKeyDB(uuid)
	if err != nil {
		return err
	}
	rec, found := db.GetByUUID(uuid)
	if !found {
		return fmt.Errorf("Cannot find record for UUID %s", uuid)
	}
	fmt.Println(uuid, rec.GetAllowedClients())
	return nil
}

// Server - let user edit key details such as mount point and mount options
func EditKey(uuid string) error {
	sys.LockMem()
	db, err := OpenKeyDB(uuid)
	if err != nil {
		return err
	}
	rec, found := db.GetByUUID(uuid)
	if !found {
		return fmt.Errorf("Cannot find record for UUID %s", uuid)
	}
	// Similar to the encryption routine, ask user all the configuration questions.
	newMountPoint := sys.Input(false, rec.MountPoint, "Mount point")
	if newMountPoint != "" {
		rec.MountPoint = newMountPoint
	}
	newOptions := sys.Input(false, strings.Join(rec.MountOptions, ","), "Mount options (space-separated)")
	if newOptions != "" {
		rec.MountOptions = strings.Split(newOptions, ",")
	}
	rec.MaxActive = sys.InputInt(false, rec.MaxActive, 1, 99999, MSG_ASK_MAX_ACTIVE)

	newAliveTimeout := sys.InputInt(false, rec.AliveIntervalSec*rec.AliveCount, DEFUALT_ALIVE_TIMEOUT, 3600*24*7, MSG_ASK_ALIVE_TIMEOUT)
	if newAliveTimeout != 0 {
		roundedAliveTimeout := newAliveTimeout / routine.REPORT_ALIVE_INTERVAL_SEC * routine.REPORT_ALIVE_INTERVAL_SEC
		if roundedAliveTimeout != newAliveTimeout {
			fmt.Printf(MSG_ALIVE_TIMEOUT_ROUNDED, roundedAliveTimeout)
		}
		rec.AliveCount = roundedAliveTimeout / routine.REPORT_ALIVE_INTERVAL_SEC
	}
	rec.AutoEncryption = sys.InputBool(rec.AutoEncryption, "Enable auto encrytion")

	if rec.AutoEncryption {
		rec.FileSystem = sys.Input(false, rec.FileSystem, "File system to be created.", "ext4", "ext3", "xfs", "btrfs")
	}

	rec.AliveCount = sys.InputInt(true, rec.AliveCount, 2, 999, "Count of keeped alive packages. Min 2")

	return UpdateRecord(db, rec)
}

// Server - show key record details but hide key content
func ShowKey(uuid string) error {
	sys.LockMem()
	db, err := OpenKeyDB(uuid)
	if err != nil {
		return err
	}
	rec, found := db.GetByUUID(uuid)
	if !found {
		return fmt.Errorf("Cannot find record for UUID %s", uuid)
	}
	rec.RemoveDeadHosts()
	fmt.Printf("%-34s%s\n", "UUID", rec.UUID)
	fmt.Printf("%-34s%s\n", "MappedName", rec.MappedName)
	fmt.Printf("%-34s%s\n", "Mount Point", rec.MountPoint)
	fmt.Printf("%-34s%s\n", "Mount Options", rec.GetMountOptionStr())
	fmt.Printf("%-34s%s\n", "Allowed Clients", rec.GetAllowedClients())
	fmt.Printf("%-34s%d\n", "Maximum Computers", rec.MaxActive)
	fmt.Printf("%-34s%s\n", "Auto Encryption", strconv.FormatBool(rec.AutoEncryption))
	fmt.Printf("%-34s%s\n", "File System", rec.FileSystem)
	fmt.Printf("%-34s%d\n", "Computer Keep-Alive Timeout (sec)", rec.AliveCount*rec.AliveIntervalSec)
	fmt.Printf("%-34s%s (%s)\n", "Last Retrieved By", rec.LastRetrieval.IP, rec.LastRetrieval.Hostname)
	outputTime := time.Unix(rec.LastRetrieval.Timestamp, 0).Format(TIME_OUTPUT_FORMAT)
	fmt.Printf("%-34s%d\n", "Last Retrieved On in sec", rec.LastRetrieval.Timestamp)
	fmt.Printf("%-34s%s\n", "Last Retrieved On", outputTime)
	fmt.Printf("%-34s%d\n", "Current Active Computers", len(rec.AliveMessages))
	if len(rec.AliveMessages) > 0 {
		// Print alive message's details from each computer
		for _, msgs := range rec.AliveMessages {
			for _, msg := range msgs {
				outputTime := time.Unix(msg.Timestamp, 0).Format(TIME_OUTPUT_FORMAT)
				fmt.Printf("%-34s%s %s (%s)\n", "", outputTime, msg.IP, msg.Hostname)
			}
		}
	}
	fmt.Printf("%-34s%d\n", "Pending Commands", len(rec.PendingCommands))
	if len(rec.PendingCommands) > 0 {
		for ip, cmds := range rec.PendingCommands {
			for _, cmd := range cmds {
				validFromStr := cmd.ValidFrom.Format(TIME_OUTPUT_FORMAT)
				validTillStr := cmd.ValidFrom.Add(cmd.Validity).Format(TIME_OUTPUT_FORMAT)
				fmt.Printf("%45s\tValidFrom=\"%s\"\tValidTo=\"%s\"\tContent=\"%v\"\tFetched? %v\tResult=\"%v\"\n",
					ip, validFromStr, validTillStr, cmd.Content, cmd.SeenByClient, cmd.ClientResult)
			}
		}
	}

	return nil
}

// SendCommand is a server routine that saves a new pending command to database record.
func SendCommand() error {
	sys.LockMem()
	client, err := keyserv.NewCryptClient("unix", keyserv.DomainSocketFile, nil, "", "")
	if err != nil {
		return err
	}
	password := sys.InputPassword(true, "", "Enter key server's password (no echo)")
	// Test the connection and password
	if err := client.Ping(keyserv.PingRequest{PlainPassword: password}); err != nil {
		return err
	}
	// Interactively gather pending command details
	uuid := sys.Input(true, "", "What is the UUID of disk affected by this command?")
	db, err := OpenKeyDB(uuid)
	if err != nil {
		return err
	}
	ip := sys.Input(true, "", "What is the IP address of computer who will receive this command?")
	var cmd string
	for {
		if cmd = sys.Input(false, "umount", "What should the computer do? (%s|%s)", PendingCommandMount, PendingCommandUmount); cmd == "" {
			cmd = "umount" // default action is "umount"
		}
		if cmd == PendingCommandUmount {
			break
		} else if cmd == PendingCommandMount {
			break
		} else {
			continue
		}
	}
	expireMin := sys.InputInt(true, 10, 1, 10080, "In how many minutes does the command expire (including the result)?")
	// Place the new pending command into database record
	rec, _ := db.GetByUUID(uuid)
	rec.AddPendingCommand(ip, keydb.PendingCommand{
		ValidFrom: time.Now(),
		Validity:  time.Duration(expireMin) * time.Minute,
		Content:   cmd,
	})
	if _, err := db.Upsert(rec); err != nil {
		return fmt.Errorf("Failed to update database record - %v", err)
	}
	// Ask server to reload the record from disk
	client.ReloadRecord(keyserv.ReloadRecordReq{PlainPassword: password, UUID: uuid})
	fmt.Printf("All done! Computer %s will be informed of the command when it comes online and polls from this server.\n", ip)
	return nil
}

// ClearPendingCommands is a server routine that clears all pending commands in a database record.
func ClearPendingCommands() error {
	sys.LockMem()
	client, err := keyserv.NewCryptClient("unix", keyserv.DomainSocketFile, nil, "", "")
	if err != nil {
		return err
	}
	password := sys.InputPassword(true, "", "Enter key server's password (no echo)")
	// Test the connection and password
	if err := client.Ping(keyserv.PingRequest{PlainPassword: password}); err != nil {
		return err
	}
	uuid := sys.Input(true, "", "What is the UUID of disk to be cleared of pending commands?")
	db, err := OpenKeyDB(uuid)
	if err != nil {
		return err
	}
	rec, _ := db.GetByUUID(uuid)
	rec.ClearPendingCommands()
	if _, err := db.Upsert(rec); err != nil {
		return fmt.Errorf("Failed to update database record - %v", err)
	}
	// Ask server to reload the record from disk
	client.ReloadRecord(keyserv.ReloadRecordReq{PlainPassword: password, UUID: uuid})
	fmt.Printf("All of %s's pending commands have been successfully cleared.\n", uuid)
	return nil
}
