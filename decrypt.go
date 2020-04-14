package main

/*
 * decrypt.go
 * Decrypt encrypted file
 * By J. Stuart McMurray
 * Created 20200411
 * Last Modified 20200413
 */

import (
	"errors"
	"io"
	"log"
	"os"

	"golang.org/x/crypto/nacl/secretbox"
)

// Decrypter decrypts files encrypted with an Encrypter
type Decrypter struct {
	Key      [32]byte /* Decryption key */
	ChunkLen int      /* Size of encrypted chunk */
	Buffer   []byte
	Nonce    [24]byte
	Out      []byte /* Open's output */
}

// Decrypt backs up the file named path and tries to decrypt it
func (d Decrypter) Decrypt(path string, info os.FileInfo, err error) error {
	/* Can only decrcypt regular, non-error files */
	if nil != err {
		log.Printf("[%s] Cannot access: %v", path, err)
		return nil
	}
	if !info.Mode().IsRegular() {
		return nil
	}

	/* Open the file to decrypt. */
	f, err := os.OpenFile(path, os.O_RDWR, 0600)
	if nil != err {
		log.Printf("[%s] Error opening: %v", path, err)
		return nil
	}
	defer f.Close()

	/* Try to read the encrypted data plus nonce */
	nr, err := io.ReadFull(f, d.Buffer)
	if nil != err && !errors.Is(err, io.ErrUnexpectedEOF) {
		log.Printf(
			"[%s] Error reading encrypted data: %v",
			f.Name(),
			err,
		)
		return nil
	}

	/* If we're not at the end of the file we'll have to read the nonce and
	overhead from the end of the file. */
	loc, err := f.Seek(0, os.SEEK_END)
	if nil != err {
		log.Printf(
			"[%s] Error seeking to end of file: %v",
			f.Name(),
			err,
		)
		return nil
	}
	var boxLen int
	if loc > int64(nr) { /* We didn't get to the end of the file */
		loc, err = f.Seek(
			int64(-(secretbox.Overhead + len(d.Nonce))),
			os.SEEK_CUR,
		)
		if nil != err {
			log.Printf(
				"[%s] Error seeking to start of overhead: %v",
				f.Name(),
				err,
			)
			return nil
		}
		if _, err := io.ReadFull(
			f,
			d.Buffer[len(d.Buffer)-
				(secretbox.Overhead+len(d.Nonce)):],
		); nil != err {
			log.Printf(
				"[%s] Error reading overhead: %v",
				f.Name(),
				err,
			)
			return nil
		}
		boxLen = d.ChunkLen + secretbox.Overhead
	} else { /* File was small */
		boxLen = nr - len(d.Nonce)
	}

	/* Copy nonce to its own array */
	copy(d.Nonce[:], d.Buffer[boxLen:boxLen+len(d.Nonce)])

	/* Decrypt the data */
	var ok bool
	d.Out, ok = secretbox.Open(
		d.Out[:0],
		d.Buffer[:boxLen],
		&d.Nonce,
		&d.Key,
	)
	if !ok {
		log.Printf("[%s] Decryption failed", f.Name())
		return nil
	}

	/* Replace the data */
	if _, err := f.Seek(0, os.SEEK_SET); nil != err {
		log.Printf(
			"[%s] Error seeking to beginning of file: %v",
			f.Name(),
			err,
		)
		return nil
	}
	if _, err := f.Write(d.Out); nil != err {
		log.Printf(
			"[%s] Error writing decrypted data: %v",
			f.Name(),
			err,
		)
		return nil
	}

	log.Printf("[%s] Decrypted", f.Name())
	return nil
}
