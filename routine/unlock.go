// cryptctl2 - Copyright (c) 2023 SUSE Software Solutions Germany GmbH, Germany
// This source code is licensed under GPL version 3 that can be found in LICENSE file.
package routine

import (
	"cryptctl2/fs"
	"cryptctl2/keydb"
	"cryptctl2/keyserv"
	"cryptctl2/sys"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"time"
)

const (
	AUTO_UNLOCK_RETRY_INTERVAL_SEC = 5
	REPORT_ALIVE_INTERVAL_SEC      = 10
)

// Forcibly unlock all file systems that have their keys on a key server.
func ManOnlineUnlockFS(progressOut io.Writer, client *keyserv.CryptClient, password string) error {
	sys.LockMem()
	// Collect information about all encrypted file systems
	blockDevs := fs.GetBlockDevices()
	reqUUIDs := make([]string, 0, 0)
	reqDevs := make(map[string]fs.BlockDevice)
	for _, dev := range blockDevs {
		if dev.MountPoint == "" && dev.IsLUKSEncrypted() && dev.UUID != "" {
			reqUUIDs = append(reqUUIDs, dev.UUID)
			reqDevs[dev.UUID] = dev
		}
	}
	if len(reqUUIDs) == 0 {
		return errors.New("Cannot find any more encrypted file systems.")
	}
	hostname, _ := sys.GetHostnameAndIP()
	resp, err := client.ManualRetrieveKey(keyserv.ManualRetrieveKeyReq{
		UUIDs:         reqUUIDs,
		Hostname:      hostname,
		PlainPassword: password,
	})
	if err != nil {
		return err
	}
	hasErr := false
	if len(resp.Granted) > 0 {
		// Unlock and mount all disks that have keys on the server
		for _, rec := range resp.Granted {
			UnlockFS(progressOut, rec, 2)
			fmt.Fprintln(progressOut)
		}
	}
	if len(resp.Missing) > 0 {
		fmt.Fprintln(progressOut, "The following encrypted file systems do not have their keys on the server:")
		for _, uuid := range resp.Missing {
			fmt.Fprintf(progressOut, "- %s %s\n", reqDevs[uuid].Path, uuid)
		}
	}
	if hasErr {
		return errors.New("Failed to process some of the encrypted file systems. Check output for more details.")
	}
	return nil
}

// Unlock a single file systems using a key record file.
func UnlockFS(progressOut io.Writer, rec keydb.Record, maxAttempts int) error {
	// Collect information from all encrypted file systems
	blockDevs := fs.GetBlockDevices()
	unlockDev, found := blockDevs.GetByCriteria(rec.UUID, "", "", "", "", "", "")
	if !found {
		return errors.New(fmt.Sprintf("Can not find device with UUID '%s'.", rec.UUID))
	}
	if !unlockDev.IsLUKSEncrypted() {
		if rec.AutoEncyption {
			if err := fs.CryptFormat(rec.Key, unlockDev.Path, unlockDev.UUID); err != nil {
				return err
			}
		} else {
			return errors.New(fmt.Sprintf("The device with UUID '%s' does not belongs to an LUKS device and AutoEncrytion is set false.", rec.UUID))
		}
	}
	// Mount the encrypted file system
	// Resume on error, in case some operations fail due to them being already carried out in previous runs.
	dmName := rec.MappedName
	if dmName == "" {
		MakeDeviceMapperName(unlockDev.Path)
	}
	dmDev := path.Join("/dev/mapper/", dmName)
	/*
		Due to race conditions in kernel it is possible for an attempt to fail without apparent reason.
		The fs.GetBlockDevice function is especially fragile in this regard, sometimes it cannot see a freshly
		mounted file system.
		Sleep a second between retries.
	*/
	fmt.Fprintf(progressOut, "Start unlocking device with UUID '%s'", rec.UUID)
	succeeded := true
	mounted := false
	for i := 0; i < maxAttempts; i++ {
		if err := fs.CryptOpen(rec.Key, unlockDev.Path, dmName); err != nil {
			fmt.Fprintf(progressOut, "  *%v\n", err)
			succeeded = false
		}
		if rec.MountPoint != "" {
			if err := os.MkdirAll(rec.MountPoint, 0755); err != nil {
				fmt.Fprintf(progressOut, "  *failed to make mount point directory - %v\n", err)
				succeeded = false
			}
			if err := fs.Mount(dmDev, "", rec.MountOptions, rec.MountPoint); err != nil {
				fmt.Fprintf(progressOut, "  *%v\n", err)
				succeeded = false
			}
			mounted = true
		}
		if succeeded {
			break
		}
		fmt.Fprintf(progressOut, "'%d'-th unlocking of device with UUID '%s' failed", i+1, rec.UUID)
		time.Sleep(1 * time.Second)
	}
	if succeeded && mounted {
		fmt.Fprintf(progressOut, "The encrypted file system has been successfully mounted on \"%s\".\n", rec.MountPoint)
	} else if succeeded {
		fmt.Fprintf(progressOut, "The encrypted file system has been successfully unlocked \"%s\".\n", rec.UUID)
	} else {
		return errors.New("Failed to process the encrypted file system. Check output for more details.")
	}
	return nil
}

/*
Make continuous attempts to retrieve encryption key from key server to unlock a file system specified by the UUID.
If maxRetrySec is zero or negative, then only one attempt will be made to unlock the file system.
*/
func AutoOnlineUnlockFS(progressOut io.Writer, client *keyserv.CryptClient, UUID string, maxRetrySec int64) error {
	sys.LockMem()
	// Keep trying until maxRetrySec elapses
	numFailures := 0
	begin := time.Now().Unix()
	for {
		// Always send the up-to-date hostname in RPC request
		hostname, _ := sys.GetHostnameAndIP()
		resp, err := client.AutoRetrieveKey(keyserv.AutoRetrieveKeyReq{
			Hostname: hostname,
			UUIDs:    []string{UUID},
		})
		if err == nil {
			rec, exists := resp.Granted[UUID]
			if exists {
				// Key has been granted by server, proceed to unlock disk.
				return UnlockFS(progressOut, rec, 3)
			}
			if len(resp.Missing) > 0 {
				// Stop trying if the server does not even have the key
				return fmt.Errorf("AutoOnlineUnlockFS: server does not have encryption key for \"%s\"", UUID)
			}
		}
		// Server may have rejected the key request due to MaxActive being exceeded
		if len(resp.Rejected) > 0 {
			err = errors.New("MaxActive is exceeded")
		}
		// Retry the operation for a while
		if time.Now().Unix() > begin+maxRetrySec {
			return fmt.Errorf("AutoOnlineUnlockFS: failed to unlock \"%s\" (%v) and have given up after %d seconds",
				UUID, err, maxRetrySec)
		}
		// In case of failure, only report the first few occasions among consecutive failures.
		if err != nil {
			if numFailures == 5 {
				fmt.Fprint(progressOut, "AutoOnlineUnlockFS: suppress further failure messages until success\n")
			} else if numFailures < 5 {
				fmt.Fprintf(progressOut, "AutoOnlineUnlockFS: failed to unlock \"%s\", will retry in %d seconds - %v\n",
					UUID, AUTO_UNLOCK_RETRY_INTERVAL_SEC, err)
			}
			numFailures++
		}
		time.Sleep(AUTO_UNLOCK_RETRY_INTERVAL_SEC * time.Second)
	}
}

/*
Continuously send alive reports to server to indicate that this computer is still holding onto the encrypted disk.
Block caller until the program quits or server rejects this computer.
*/
func ReportAlive(progressOut io.Writer, client *keyserv.CryptClient, uuid string) error {
	fmt.Fprintf(progressOut, "ReportAlive: begin sending messages for encrypted disk \"%s\"\n", uuid)
	numFailures := 0
	for {
		// Always send the up-to-date hostname in RPC request
		hostname, _ := sys.GetHostnameAndIP()
		rejected, err := client.ReportAlive(keyserv.ReportAliveReq{
			Hostname: hostname,
			UUIDs:    []string{uuid},
		})
		if len(rejected) > 0 {
			return fmt.Errorf("ReportAlive: stop sending messages for disk \"%s\" because server has rejected it", uuid)
		}
		// In case of failure, only report the first few occasions among consecutive failures.
		if err == nil {
			if numFailures > 0 {
				fmt.Fprintf(progressOut, "ReportAlive: succeeded for disk \"%s\"\n", uuid)
			}
			numFailures = 0
		} else {
			if numFailures == 5 {
				fmt.Fprint(progressOut, "ReportAlive: suppress further failure messages until next success\n")
			} else if numFailures < 5 {
				fmt.Fprintf(progressOut, "ReportAlive: failed to send message for disk \"%s\" - %v\n", uuid, err)
			}
			numFailures++
		}
		time.Sleep(REPORT_ALIVE_INTERVAL_SEC * time.Second)
	}
}

/*
Erase encryption metadata on the specified disk, and then ask server to erase its key.
This process renders all data on the disk irreversibly lost.
*/
func EraseKey(progressOut io.Writer, client *keyserv.CryptClient, password, uuid string) error {
	// Find the device node and erase the encryption metadata
	blkDevs := fs.GetBlockDevices()
	hostDev, foundHost := blkDevs.GetByCriteria(uuid, "", "", "", "", "", "")
	if !foundHost {
		return fmt.Errorf("EraseKey: cannot find a block device corresponding to UUID \"%s\"", uuid)
	}
	unlockedDevPath := MakeDeviceMapperName(hostDev.Path)
	unlockedDev, foundUnlocked := blkDevs.GetByCriteria("", path.Join("/dev/mapper", unlockedDevPath), "", "", "", "", "")
	if foundUnlocked {
		// Unmount and close it before erasing the data
		if unlockedDev.MountPoint != "" {
			fmt.Fprintf(progressOut, "Umounting \"%s\"...\n", unlockedDev.MountPoint)
			if err := fs.Umount(unlockedDev.MountPoint); err != nil {
				return err
			}
		}
		fmt.Fprintf(progressOut, "Closing \"%s\"...\n", unlockedDevPath)
		if err := fs.CryptClose(unlockedDevPath); err != nil {
			return err
		}
	}
	if err := fs.CryptErase(hostDev.Path); err != nil {
		return err
	}
	// After metadata is erased, ask server to remove its key record as well.
	hostname, _ := sys.GetHostnameAndIP()
	if err := client.EraseKey(keyserv.EraseKeyReq{
		PlainPassword: password,
		Hostname:      hostname,
		UUID:          uuid}); err != nil {
		return err
	}
	fmt.Fprintf(progressOut, "Encryption header has been wiped successfully, data in \"%s\" (%s) is now irreversibly lost.\n",
		uuid, hostDev.Path)
	return nil
}
