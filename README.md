Toy Ransomware
==============
This is not-very-good ransomware meant to be used as a PoC or test of defensive
capabilities (until someone signatures it).

To use it, just run it.  It will encrypt the first chunk of all files in
`$HOME` by default.

Please run (in a throwaway VM) with `-h` for a complete list of options.
Listing the options won't encrypt files, but typos happen.

For legal use only.

Building
--------
Like any other go project, though hopefully not with `go install`.

```bash
go get github.com/magisterquis/toyransomware
go build github.com/magisterquis/toyransomware # Maybe set $GOOS
```

Encryption
----------
Only the first chunk (`-chunklen`, default 1k) of a file is encrypted.
Encryption is done by taking the SHA256 hash of a pair of random numbers,
generating a random nonce, and passing that all to
[`secretbox.Seal`](https://godoc.org/golang.org/x/crypto/nacl/secretbox#Seal).
The overhead from generating authenticatable ciphertext as well as the nonce
are appended to the file after the chunk is overwritten with ciphertext.

By default all files in `$HOME` are encrypted.  This can be changed with
`-root` to set the root of the directory tree in which files will be decrypted.
`/var` would be bad.  `/proc` wouldn't probably do much.

The names of files can be controlled by specifing a regular expression with
`-regex`.  This can be used to limit encryption to specific file names (e.g.
`\.docx?$`).

The Key
-------
The key is composed of a secret key and an ID, both base36-encrypted uint64s.
The full key is sent via a DNS request to a configurable domain (`-domain`).
This should probably be changed from `example.com` to something controlled by
whomever is using this.  The DNS queries should be caught and logged in order
to have a list of encryption keys to use.  There is no DNS server provided as
part of this project (yet?).

The queries will look something like `3nfpvvv7qwlll.3w4alyv2o2x6c.example.com`.

The first base36 number (`3nfpvvv7qwlll`) is secret.  It is sent to the
attacker via DNS and never seen again unless the ransom is paid.  Woe be unto
the defender who blocks DNS to the attacker for he will never see the first
kilobyte of his files again.

The second base36 number (`3w4alyv2o2x6c`) is put in the ransom note.  Please
supply it when paying the ransom as the bad guy will need to know which secret
to send you.

Both together, separated by a dot (`3nfpvvv7qwlll.3w4alyv2o2x6c`) are what is
needed to decrypt files (with `-decrypt`).

Backups
-------
Encrypted files will first be backed up to a file with the same name as the
file to be encrypted with a suffix added, by default `.etrbak` (controllable
with `-encryption-suffix`).  These are there should you find yourself having
typo'd something like `./toymalware - h`.

Ransom Note
----------
A cheesy ransom note is left in every directory touched during encryption.  If
testing something which looks for a `.onion` address in the ransom note or
something along those lines, it'll need to be changed.  See
[`note.go`](./note.go).  NB: The note template will be passed to 
[`fmt.Sprintf`](https://golang.org/pkg/fmt/#Sprintf) with a single string
argument containing the ID to put in the note.

The note contains the ID needed to give to the bad guy to get the decryption
key.  Don't lose it.
