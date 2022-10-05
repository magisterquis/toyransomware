package main

/*
 * toyramsomware_test.go
 * Tests for the toy ransomware
 * By J. Stuart McMurray
 * Created 20221004
 * Last Modified 20221004
 */

import (
	"bytes"
	"fmt"
	"io"
	"math/rand"
	"os"
	"testing"
)

func testEncryptDecryptFile(enc Encrypter, dec Decrypter, b []byte) error {
	f, err := os.CreateTemp("", "")
	if nil != err {
		return fmt.Errorf("creating file: %w", err)
	}
	defer f.Close()
	defer os.Remove(f.Name())

	if _, err := f.Write(b); nil != err {
		return fmt.Errorf("populating file %s: %w", f.Name(), err)
	}

	if _, err := f.Seek(0, os.SEEK_SET); nil != err {
		return fmt.Errorf(
			"seeking to beginning of file %s for encrypting: %w",
			f.Name(),
			err,
		)
	}
	if err := enc.EncryptFile(f); nil != err {
		return fmt.Errorf("encrypting file %s: %w", f.Name(), err)
	}

	if _, err := f.Seek(0, os.SEEK_SET); nil != err {
		return fmt.Errorf(
			"seeking to beginning of file %s for "+
				"encrypted read: %w",
			f.Name(),
			err,
		)
	}
	e, err := io.ReadAll(f)
	if nil != err {
		return fmt.Errorf(
			"reading encrypted file %s: %w",
			f.Name(),
			err,
		)
	}

	if _, err := f.Seek(0, os.SEEK_SET); nil != err {
		return fmt.Errorf(
			"seeking to beginning of file %s for decryption: %w",
			f.Name(),
			err,
		)
	}
	if err := dec.DecryptFile(f); nil != err {
		return fmt.Errorf("decrypting file %s: %w", f.Name(), err)
	}

	if _, err := f.Seek(0, os.SEEK_SET); nil != err {
		return fmt.Errorf(
			"seeking to beginning of file %s for read: %w",
			f.Name(),
			err,
		)
	}
	r, err := io.ReadAll(f)
	if nil != err {
		return fmt.Errorf(
			"reading decrypted file %s: %w",
			f.Name(),
			err,
		)
	}

	if !bytes.Equal(r, b) {
		return fmt.Errorf(
			"encrypt/decrypt failed plaintext:%q "+
				"encrypted:%q decrypted:%q",
			b,
			e,
			r,
		)
	}

	return nil
}

func TestEncryptDecrypt(t *testing.T) {
	chunkLen := 1024
	randBytes := func(n int) []byte {
		b := make([]byte, n)
		if _, err := rand.Read(b); nil != err {
			panic(err)
		}
		return b
	}
	e := Encrypter{Message: make([]byte, chunkLen), BackupSuffix: "etrbak"}
	copy(e.Key[:], randBytes(len(e.Key)))
	d := Decrypter{Key: e.Key, BackupSuffix: "etrbak"}
	for _, c := range []struct {
		n string
		b []byte
	}{
		{n: "short", b: []byte("Billy")},
		{n: "10 zeros", b: make([]byte, 10)},
		{n: "1023 zeros", b: make([]byte, 1023)},
		{n: "1024 zeros", b: make([]byte, 1024)},
		{n: "1025 zeros", b: make([]byte, 1025)},
		{n: "2048 zeros", b: make([]byte, 2048)},
		{n: "10 random bytes", b: randBytes(10)},
		{n: "1023 random bytes", b: randBytes(1023)},
		{n: "1024 random bytes", b: randBytes(1024)},
		{n: "1025 random bytes", b: randBytes(1025)},
		{n: "2048 random bytes", b: randBytes(2048)},
	} {
		if err := testEncryptDecryptFile(e, d, c.b); nil != err {
			t.Errorf("TestEncryptDecrypt: %s: %s", c.n, err)
		}
	}
}
