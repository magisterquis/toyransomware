package main

/*
 * decrypt.go
 * Decrypt encrypted file
 * By J. Stuart McMurray
 * Created 20200411
 * Last Modified 20221004
 */

import (
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"math"
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

	/* If it doesn't start with at least one NUL, it's not ours. */
	var zb [1]byte
	if _, err := io.ReadFull(f, zb[:]); nil != err {
		log.Printf(
			"[%s] Error reading first byte of file: %s",
			path,
			err,
		)
	}
	if 0 != zb[0] {
		log.Printf("[%s] Does not seem encrypted", path)
		return nil
	}
	if _, err := f.Seek(0, os.SEEK_SET); nil != err {
		log.Printf(
			"[%s] Error seeking to beginning of file: %s",
			path,
			err,
		)
	}

	/* Decrypt the file. */
	if err := d.DecryptFile(f); nil != err {
		log.Printf("[%s] Error decrypting: %s", path, err)
	}

	log.Printf("[%s] Decrypted", f.Name())
	return nil
}

// DecryptFile decrypts the single file f.
func (d Decrypter) DecryptFile(f *os.File) error {
	/* Work out how many bytes of encrypted chunk to read. */
	var clb [8]byte
	if _, err := f.Seek(-8, os.SEEK_END); nil != err {
		return fmt.Errorf("seeking to end of file: %w", err)
	}
	if _, err := io.ReadFull(f, clb[:]); nil != err {
		return fmt.Errorf("reading chunk size: %w", err)
	}
	cl64 := binary.BigEndian.Uint64(clb[:])
	if uint64(math.MaxInt) < cl64 {
		return fmt.Errorf("encrypted chunk size %d too large", cl64)
	}
	cl := int(cl64)
	if cap(d.Buffer) < cl {
		d.Buffer = make([]byte, cl)
	} else {
		d.Buffer = d.Buffer[:cl]
	}

	/* Seek to beginning of our bit. */
	ol := int64(len(d.Nonce)) + int64(len(d.Buffer)) + 8
	flen, err := f.Seek(
		-1*ol,
		os.SEEK_END,
	)
	if nil != err {
		return fmt.Errorf("seeking to beginning of payload: %w", err)
	}

	/* Get the nonce and encrypted chunk. */
	if _, err := io.ReadFull(f, d.Nonce[:]); nil != err {
		return fmt.Errorf("reading nonce: %w", err)
	}
	if _, err := io.ReadFull(f, d.Buffer); nil != err {
		return fmt.Errorf("reading encrypted chunk: %w", err)
	}

	/* Decrypt the payload */
	var ok bool
	d.Out, ok = secretbox.Open(d.Out[:0], d.Buffer, &d.Nonce, &d.Key)
	if !ok {
		return fmt.Errorf("decryption failed")
	}

	/* Replace the original zeroed bytes */
	if _, err := f.WriteAt(d.Out, 0); nil != err {
		return fmt.Errorf("putting plaintext back: %w", err)
	}

	/* Remove the encryption chunk from the end. */
	if err := f.Truncate(flen); nil != err {
		return fmt.Errorf("removing encryption chunk: %w", err)
	}

	return nil
}
