# Sig

Sig is a robust command-line utility written in Go for signing, verifying, inspecting, and fetching signed documents. Leveraging Ed25519 cryptography, Sig ensures the integrity and authenticity of your documents through a simple and efficient workflow.

**Disclaimer:** Always ensure you protect your private keys and handle cryptographic operations securely. Use it responsibly to maintain the security and integrity of your documents.

## Table of Contents

- [Features](#features)
  - [Benefits](#benefits)
- [Installation](#installation)
- [Usage](#usage)
  - [Signing a Document](#signing-a-document)
  - [Verifying a Document](#verifying-a-document)
  - [Inspecting Signatures](#inspecting-signatures)
  - [Displaying Key Fingerprints](#displaying-key-fingerprints)
  - [Fetching Signed Documents](#fetching-signed-documents)
- [Sig File Format](#sig-file-format)
- [Contributing](#contributing)
- [License](#license)

## Features

- **Sign Documents**: Create digital signatures or append signatures to existing documents.
- **Verify Signatures**: Authenticate documents using public keys.
- **Inspect Signatures**: View all signatures attached to a document.
- **Key Fingerprinting**: Display fingerprints for public/private keys.
- **Fetch Documents**: Download, verify, and unpack documents efficiently.

### Benefits

- **Security**: Sig utalizes Ed25519 signature system that provides strong security guarantees.
- **Simplicity**: Straightforward command-line interface for signing and verification tasks.
- **Flexibility**: Supports both gzipped and non-gzipped input formats.
- **Efficiency**: ETag support minimizes unnecessary downloads when fetching documents.
- **Scalability**: Allows multiple signatures to be appended to a single document.
- **Portability**: Written in Go, making it cross-platform compatible.
- **Integration**: Easily integrated into CI/CD pipelines and shell scripts.

## Installation

Ensure you have [Go](https://golang.org/dl/) installed (version 1.20 or later).

```bash
git clone https://github.com:claytonsingh/tools.git
cd tools/sig
go build -o sig sig.go
```

Move the executable to a directory in your `PATH` for easy access:

```bash
mv sig /usr/local/bin/
```

## Usage

Sig offers several commands to manage signed documents. Below are the primary commands and their usages.

Though in the examples below the document is just text, Sig can sign any file type. It is common to sign tar files with the extension `.tar.sig.gz` or `.tsz`.

### Generating Keys

Before using Sig, you need to generate a key pair. Use the following OpenSSL commands to generate Ed25519 private and public keys:

```bash
# Generate a private key
openssl genpkey -algorithm ed25519 -out private_key.pem

# Generate the public key from the private key
openssl pkey -in private_key.pem -out public_key.pem -pubout
```

Keep your private key secure and only share the public key with others who need to verify your signatures.

### Signing a Document

Sign a new document or append a signature to an existing one. The input may optionally be gzip compressed. The outout will always be gzip compressed.

Multiple private keys can be provided and all signatures will be appended.

```bash
# Sign a document and output to stdout
cat document.txt    | sig sign your_private_key.pem > document.sig.gz
cat document.txt.gz | sig sign your_private_key.pem > document.sig.gz

# Sign a document and save the signed version
sig sign --if document.txt    --of signed_document.sig.gz your_private_key.pem
sig sign --if document.txt.gz --of signed_document.sig.gz your_private_key.pem

# Append multiple signature to an existing signed document
cat signed_document.sig    | sig sign your_private_key.pem your_other_private_key.pem > updated_signed_document.sig.gz
cat signed_document.sig.gz | sig sign your_private_key.pem your_other_private_key.pem > updated_signed_document.sig.gz
```

### Verifying a Document

Verify the signatures of a signed document and unpack its content. The input may optionally be gzip compressed. The outout will always be uncompressed.

Multiple public or private keys can be provided. Only keys that have a fingerprint match will be used to validate the document.

```bash
# Verify and unpack to stdout
cat signed_document.sig    | sig verify your_public_key.pem > verified_document.txt
cat signed_document.sig.gz | sig verify your_public_key.pem > verified_document.txt

# Verify and save the unpacked document
cat signed_document.sig    | sig verify --of verified_document.txt your_public_key.pem
cat signed_document.sig.gz | sig verify --of verified_document.txt your_public_key.pem

# Verify and unpack using multiple keys and the input file and output file flags
sig verify --if signed_document.sig    --of verified_document.txt your_public_key.pem your_other_public_key.pem
sig verify --if signed_document.sig.gz --of verified_document.txt your_public_key.pem your_other_private_key.pem
```

### Fetching Signed Documents

Download a signed document from a URL, verify its signature, and unpack the content. If the fetched document is gzip compressed it is extracted.

When using the `--etag` flag the ETag is loaded and saved to a file to be used for subsequent fetches. If the ETag matches the server the document is not fetched again and sig exits with code 3.

Multiple public or private keys can be provided. Only keys that have a fingerprint match will be used to validate the document.

```bash
# Fetch, verify, and unpack a document
sig fetch https://example.com/document.sig your_public_key.pem > downloaded_document.txt
sig fetch --of downloaded_document.txt https://example.com/document.sig your_public_key.pem

# Fetch with ETag support
sig fetch --etag etag_storage.txt https://example.com/document.sig.gz your_public_key.pem > downloaded_document.txt
sig fetch --of downloaded_document.txt --etag etag_storage.txt https://example.com/document.sig.gz your_public_key.pem
```

### Inspecting Signatures

Display all fingerprints of signatures present in a signed document. The input may optionally be gzip compressed.

```bash
# Inspect signatures from stdin
cat signed_document.sig    | sig inspect
cat signed_document.sig.gz | sig inspect

# Inspect signatures using the input file
sig inspect --if signed_document.sig
sig inspect --if signed_document.sig.gz
```

### Displaying Key Fingerprints

Show fingerprints for public or private keys to easily identify them.

Multiple public or private keys can be provided.

```bash
# Display fingerprint for a public key
sig fingerprint your_public_key.pem

# Display fingerprint for a private key
sig fingerprint your_private_key.pem

# Display fingerprint for multiple keys
sig fingerprint your_private_key.pem your_public_key.pem
```

## Sig File Format

Sig uses a simple structured format to store document content along with its signatures. It consists of two main parts:

1. Document Content
2. Signature Section

### Structure

```
[Document Content]
\n\nsig-0.1\n
[Fingerprint1]:[Signature1]\n
[Fingerprint2]:[Signature2]\n
...
[FingerprintN]:[SignatureN]\n
```

### Details

- **Document Content**: The original data being signed.
- **Signature Section**: Starts after the last double newline (`\n\n`) with `sig-0.1` indicating the format version.
- **Fingerprints**: 20-byte base64-encoded strings derived from public keys.
- **Signatures**: Base64-encoded Ed25519 signatures.
- **Capacity**: Supports up to 1213 signatures within the 128 KB limit.

## Contributing

Contributions are welcome! Open a pull request.

## License

```
MIT License

Copyright (c) 2024 Clayton Singh

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```
