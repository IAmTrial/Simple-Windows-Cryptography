# Simple Windows Cryptography
A project for interfacing with the Windows Cryptography functions.

Written to be functional on Windows 95/98/ME and other systems supported by WINE.

## How to Use
This is a simple command-line program for Windows. Upon launching the program, a help screen will describe what parameters are available.

The main options are:
- generate: Generate a public/private key pair.
- sign: Sign a file using a private key.
- verify: Verify that a digital signature matches with a given file and verification key.

Upon specifying an option with no other parameters, the program will print the usage template for that option. Some options may be restricted on Windows 95/98/ME systems, due to certain newer features not being available. If applicable, a message will also be printed noting this.

## Generating a Public/Private Key
```
swincrypt.exe generate [sign|encdec] publickey privatekey
```
- \[sign|encdec\]: Whether to generate a pair of signing keys, or encryption/decryption keys.
- publickey: The output path to the public key file.
- privatekey: The output path for the private key file.

Example:
```
swincrypt.exe generate sign public.key private.key
```

## Signing a File
```
swincrypt.exe sign [md2|md4|md5|sha-1|sha-256|sha-384|sha-512] privatekey inputfile outputfile
```
- \[md2|md4|md5|sha-1|sha-256|sha-384|sha-512\]: Determines which algorithm to use to generate the file hash.
- privatekey: The path to the private key file.
- inputfile: The path to the file to be hashed.
- outputfile: The output path for the signature file.

Example:
```
swincrypt.exe sign sha-1 private.key abc.txt abc.sha1sig
```

## Verifying a Signature
```
swincrypt.exe verify [md2|md4|md5|sha-1|sha-256|sha-384|sha-512] publickey inputfile outputfile
```
- \[md2|md4|md5|sha-1|sha-256|sha-384|sha-512\]: Determines which algorithm to use to generate the file hash.
- publickey: The path to the public key file.
- inputfile: The path to the file to be hashed.
- outputfile: The output path for the signature file.

Example:
```
swincrypt.exe verify sha-1 public.key abc.txt abc.sha1sig
```

## For Windows 95/98/ME
On Windows 95/98/ME, only the MD2, MD4, MD5, SHA-1 hashing algorithms are available.
