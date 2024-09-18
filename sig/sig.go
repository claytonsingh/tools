package main

import (
	"bytes"
	"compress/gzip"
	"crypto"
	"crypto/ed25519"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"

	"github.com/claytonsingh/golib/peekbuffer"
	"github.com/jessevdk/go-flags"
)

/*
Sig File Format

The sig file format is a simple structure for signing and verifying documents. It consists of two main parts:

1. Document Content
2. Signature Section

Structure:

    [Document Content]
    \n\n
    sig-0.1\n
    [Fingerprint1]:[Signature1]\n
	...
    [FingerprintN]:[SignatureN]\n
    [EOF]

Details:

- The document content is the original data being signed.
- The last instance of a double newline (\n\n) in the file separates the content from the signature section.
- The signature section starts with "sig-0.1" to indicate the format version.
- Each subsequent line contains a fingerprint and signature pair, separated by a colon.
- Fingerprints are 20-character base64-encoded strings (120 bits) derived from the public key.
- Signatures are base64-encoded Ed25519 signatures.
- The signature section can accommodate up to 1213 individual signatures within the 128 KB limit.
- Multiple signatures can be added to the same document.
- The signature section is always after the end of the file, after the last double newline.
*/

// Operatations
// -- Sign new document or append signature to existing
// cat file.tar        | sig --sign test.key > new.tar.sig.gz
// cat file.tar.gz     | sig --sign test.key > new.tar.sig.gz
// cat file.tar.sig    | sig --sign test.key > new.tar.sig.gz
// cat file.tar.sig.gz | sig --sign test.key > new.tar.sig.gz
//
// -- Show fingerprint for public/private keys
// sig --fingerprint test.key
// sig --fingerprint test.pub
//
// -- Inspect fingerprints for a document
// cat file.tar.sig    | sig --inspect
// cat file.tar.sig.gz | sig --inspect
//
// -- Verify and unpack document
// cat file.tar.sig    | sig --verify test.pub > file.tar; echo $?
// cat file.tar.sig.gz | sig --verify test.pub > file.tar; echo $?
//
// -- Download, verify, and unpack document with etag/last modified date
// sig --fetch='http://example.com/file.tar.sig.gz' --etag=tags/file test.pub > new.tar; echo $?
// sig --fetch='http://example.com/file.tar.sig'    --etag=tags/file test.pub > new.tar; echo $?

const FooterPrefix = "sig-"
const MaxFooterSize = 1024 * 128
const FingerprintSize = 15 // 15 bytes = 120 bits

var ErrNotModified = fmt.Errorf("content not modified")

type opts struct {
	CmdFetch struct {
		ETag    string `long:"etag" description:"File to check and store the ETag. Exit code 3 if content unchanged."`
		FileOut string `long:"of"   description:"Output file path (default: stdout)" default:"-" default-mask:"-"`
		//FileTemp string `long:"temp" description:"path to temporarily store the downloading artifact." default:"-" default-mask:"-"`
		Args struct {
			URL  string   `positional-arg-name:"url" required:"yes" description:"URL of the document to fetch"`
			Keys []string `positional-arg-name:"keys" required:"1" description:"Public/private key files for verification"`
		} `positional-args:"yes" required:"yes"`
	} `command:"fetch" description:"Fetch, verify, and unpack a remote document"`

	CmdFingerprint struct {
		Args struct {
			Keys []string `positional-arg-name:"keys" required:"1" description:"Public/private key files to fingerprint"`
		} `positional-args:"yes" required:"yes"`
	} `command:"fingerprint" description:"Display fingerprints for public/private keys"`
	CmdInspect struct {
		FileIn string `long:"if" description:"Input file path (default: stdin)" default:"-" default-mask:"-"`
	} `command:"inspect" description:"Display fingerprints of signatures in a document"`

	CmdSign struct {
		FileIn  string `long:"if" description:"Input file path (default: stdin)" default:"-" default-mask:"-"`
		FileOut string `long:"of" description:"Output file path (default: stdout)" default:"-" default-mask:"-"`
		//FileTemp string `long:"temp" description:"path to temporarily store the downloading artifact." default:"-" default-mask:"-"`
		Args struct {
			Keys []string `positional-arg-name:"keys" required:"1" description:"Private key files for signing"`
		} `positional-args:"yes" required:"yes"`
	} `command:"sign" description:"Sign a new document or add signatures to an existing one"`

	CmdVerify struct {
		FileIn  string `long:"if" description:"Input file path (default: stdin)" default:"-" default-mask:"-"`
		FileOut string `long:"of" description:"Output file path (default: stdout)" default:"-" default-mask:"-"`
		//FileTemp string `long:"temp" description:"path to temporarily store the downloading artifact." default:"-" default-mask:"-"`
		Args struct {
			Keys []string `positional-arg-name:"keys" required:"1" description:"Public/private key files for verification"`
		} `positional-args:"yes" required:"yes"`
	} `command:"verify" description:"Verify and unpack a signed document"`
}

func main() {
	os.Exit(run(os.Args[1:]))

	// os.Exit(run([]string{"fingerprint", "test.key", "test.pub", "x"}))
	// os.Exit(run([]string{"sign", "--if=test.txt.sig", "--of=test.txt.sig.gz", "test.key"}))
	// os.Exit(run([]string{"inspect", "--if=test.txt.sig.gz"}))
	// os.Exit(run([]string{"verify", "--if=test.txt.sig.gz", "--of=test-of.txt", "test.key"}))
	// os.Exit(run([]string{"fetch", "--of=download.txt", "https://test.gacl.ca/test.txt.sig.gz", "test.key"}))
	// os.Exit(run([]string{"fetch", "--of=download.txt", "--etag=etag", "https://test.gacl.ca/test.txt.sig.gz", "test.key"}))
}

func run(args []string) int {
	var opts opts
	p := flags.NewParser(&opts, flags.Default)
	if _, err := p.ParseArgs(args); err != nil {
		return 1
	}

	switch p.Active.Name {
	case "fetch":
		if err := cmdVerify(
			true,
			opts.CmdFetch.Args.Keys,
			opts.CmdFetch.Args.URL,
			opts.CmdFetch.FileOut,
			opts.CmdFetch.ETag,
		); err != nil {
			fmt.Fprintf(os.Stderr, "Error in fetch command: %v\n", err)
			return 1
		}
	case "fingerprint":
		{
			for _, file := range opts.CmdFingerprint.Args.Keys {
				prKeyBytes, err := os.ReadFile(file)
				if err != nil {
					fmt.Fprintln(os.Stderr, "Unable to read file:", file)
					return 1
				}
				keys, err := loadPubKeys(prKeyBytes)
				if err != nil {
					fmt.Fprintln(os.Stderr, "Error loading public keys from file:", file, ":", err)
					return 1
				}
				for _, key := range keys {
					fmt.Println(key.Fingerprint(), file)
				}
			}
		}
	case "inspect":
		if err := cmdInspect(opts); err != nil {
			fmt.Fprintf(os.Stderr, "Error in inspect command: %v\n", err)
			return 1
		}
	case "sign":
		if err := cmdSign(opts); err != nil {
			fmt.Fprintf(os.Stderr, "Error in sign command: %v\n", err)
			return 1
		}
	case "verify":
		if err := cmdVerify(
			false,
			opts.CmdVerify.Args.Keys,
			opts.CmdVerify.FileIn,
			opts.CmdVerify.FileOut,
			"", // etagPath is not used for verify
		); err != nil {
			if err == ErrNotModified {
				fmt.Fprintln(os.Stderr, "Content not modified")
				return 3
			} else {
				fmt.Fprintf(os.Stderr, "Error in verify command: %v\n", err)
				return 1
			}
		}
	default:
		return 1
	}
	return 0
}

func cmdSign(opts opts) error {
	var fi, ft *os.File

	// Open for reading (and sometimes writing if in and out are the same)
	if d, err := openInput(opts.CmdSign.FileIn, &fi); err != nil {
		return fmt.Errorf("failed to open input file: %w", err)
	} else {
		defer d()
	}

	if d, err := openTemp(&ft); err != nil {
		return fmt.Errorf("failed to create temporary file: %w", err)
	} else {
		defer d()
	}

	// Process input
	tmp := gzip.NewWriter(ft)

	keys, err := loadPriKeysFromFiles(opts.CmdSign.Args.Keys)
	if err != nil {
		return fmt.Errorf("failed to load private keys: %w", err)
	}

	hash, signatures, _, err := UnpackDocument(fi, tmp)
	if err != nil {
		return fmt.Errorf("failed to unpack document: %w", err)
	}

	for _, key := range keys {
		f := key.Fingerprint()
		s, err := key.Sign(hash)
		if err != nil {
			return fmt.Errorf("failed to make signature: %w", err)
		}
		signatures[f] = s
	}

	if err := WriteSignatures(tmp, signatures); err != nil {
		return err
	}

	if err := tmp.Close(); err != nil {
		return fmt.Errorf("failed to close gzip writer: %w", err)
	}

	// Write out content
	if err := ft.Sync(); err != nil {
		return fmt.Errorf("failed to sync temporary file: %w", err)
	}
	if _, err := ft.Seek(0, 0); err != nil {
		return fmt.Errorf("failed to seek temporary file: %w", err)
	}
	if opts.CmdSign.FileOut == "-" {
		if _, err := io.Copy(os.Stdout, ft); err != nil {
			return fmt.Errorf("failed to copy to stdout: %w", err)
		}
	} else if opts.CmdSign.FileOut == opts.CmdSign.FileIn {
		// If in and out are the same then seek, truncate, and write
		if _, err := fi.Seek(0, 0); err != nil {
			return fmt.Errorf("failed to seek output file: %w", err)
		}
		if err := fi.Truncate(0); err != nil {
			return fmt.Errorf("failed to truncate output file: %w", err)
		}
		if _, err := io.Copy(fi, ft); err != nil {
			return fmt.Errorf("failed to copy to output file: %w", err)
		}
	} else {
		file, err := os.Create(opts.CmdSign.FileOut)
		if err != nil {
			return fmt.Errorf("failed to create output file: %w", err)
		}
		defer file.Close()

		if _, err := io.Copy(file, ft); err != nil {
			return fmt.Errorf("failed to copy to output file: %w", err)
		}
	}

	return nil
}

func cmdInspect(opts opts) error {
	var fi *os.File
	if d, err := openInput(opts.CmdInspect.FileIn, &fi); err != nil {
		return fmt.Errorf("failed to open input file: %w", err)
	} else {
		defer d()
	}

	_, signatures, _, err := UnpackDocument(fi, io.Discard)
	if err != nil {
		return fmt.Errorf("failed to unpack document: %w", err)
	}

	// Collect signatures into a slice and sort them
	var signatureList []string
	for signature := range signatures {
		signatureList = append(signatureList, signature)
	}
	sort.Strings(signatureList)

	// Print sorted signatures
	for _, signature := range signatureList {
		fmt.Println(signature)
	}
	return nil // Return nil if successful
}

func cmdVerify(isFetch bool, keys []string, inputSource string, outputDest string, etagPath string) error {
	var ft, fi *os.File
	var reader io.Reader

	pubKeys, err := loadPubKeysFromFiles(keys)
	if err != nil {
		return fmt.Errorf("failed to load public keys: %w", err)
	}

	if d, err := openTemp(&ft); err != nil {
		return fmt.Errorf("failed to create temporary file: %w", err)
	} else {
		defer d()
	}

	if isFetch {
		// Fetch logic
		resp, err := fetchWithETag(inputSource, etagPath)
		if err != nil {
			return fmt.Errorf("failed to fetch with ETag: %w", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusNotModified {
			return ErrNotModified
		}

		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
		}

		reader = resp.Body
	} else {
		// Verify logic
		if d, err := openInput(inputSource, &fi); err != nil {
			return fmt.Errorf("failed to open input file: %w", err)
		} else {
			defer d()
		}
		reader = fi
	}

	ok, err := UnpackAndVerifyDocument(reader, ft, pubKeys)
	if err != nil {
		return fmt.Errorf("failed to unpack and verify document: %w", err)
	}

	if !ok {
		return fmt.Errorf("verification failed: no matching key found")
	}

	// Common output handling
	if err := ft.Sync(); err != nil {
		return fmt.Errorf("failed to sync temporary file: %w", err)
	}
	if _, err := ft.Seek(0, 0); err != nil {
		return fmt.Errorf("failed to seek temporary file: %w", err)
	}

	if outputDest == "-" {
		if _, err := io.Copy(os.Stdout, ft); err != nil {
			return fmt.Errorf("failed to copy to stdout: %w", err)
		}
	} else if !isFetch && outputDest == inputSource {
		if _, err := fi.Seek(0, 0); err != nil {
			return fmt.Errorf("failed to seek output file: %w", err)
		}
		if err := fi.Truncate(0); err != nil {
			return fmt.Errorf("failed to truncate output file: %w", err)
		}
		if _, err := io.Copy(fi, ft); err != nil {
			return fmt.Errorf("failed to copy to output file: %w", err)
		}
	} else {
		file, err := os.Create(outputDest)
		if err != nil {
			return fmt.Errorf("failed to create output file: %w", err)
		}
		defer file.Close()

		if _, err := io.Copy(file, ft); err != nil {
			return fmt.Errorf("failed to copy to output file: %w", err)
		}
	}

	return nil
}

// UnpackAndVerifyDocument reads and unpacks a document, verifies its signatures, and writes the content to the provided writer.
//
// Parameters:
//   - reader io.Reader: The source from which to read the signed document.
//   - writer io.Writer: The destination to write the unpacked document content.
//   - keys []ed25519.PublicKey: A slice of public keys to use for signature verification.
//
// Returns:
//   - ok bool: True if the document was successfully unpacked and at least one signature was verified, false otherwise. If ok is false and e is nil, it means no matching key was found for verification.
//   - e error: Any error encountered during the unpacking or verification process.
//
// The function first unpacks the document using UnpackDocument. If signatures are found and no errors occur during unpacking,
// it attempts to verify the document's hash against each provided public key. The function returns true if any key successfully
// verifies the signature, indicating the document is authentic according to at least one of the provided keys.
func UnpackAndVerifyDocument(reader io.Reader, writer io.Writer, keys []CryptoKey) (ok bool, e error) {
	hash, signatures, found, err := UnpackDocument(reader, writer)
	if err == nil && found {
		for _, key := range keys {
			if signature, ok := signatures[key.Fingerprint()]; ok {
				sig, _ := base64.RawStdEncoding.DecodeString(signature)
				if key.Verify(hash, sig) == nil {
					return true, nil
				}
				//if Verify(hash, key, sig) == nil {
				//	return true, nil
				//}
			}
		}
	}
	return false, err
}

// UnpackDocument reads and unpacks a document from the provided reader, writes the content to the writer,
// and extracts any signatures present. It supports both gzipped and non-gzipped input.
//
// Parameters:
//   - reader io.Reader: The source from which to read the document.
//   - writer io.Writer: The destination to write the unpacked document content.
//
// Returns:
//   - []byte: The SHA-512 hash of the document content.
//   - map[string]string: A map of fingerprints to their corresponding signatures, if present.
//   - bool: True if signatures were found, false otherwise.
//   - error: Any error encountered during the unpacking process.
//
// The function reads the document in chunks, looking for a signature section at the end.
// If found, it separates the signatures from the document content. The content is written
// to the provided writer and hashed. If no signature section is found, it processes the
// entire input as document content.
func UnpackDocument(reader io.Reader, writer io.Writer) ([]byte, map[string]string, bool, error) {

	pReader := peekbuffer.NewPeekBuffer(reader)
	// Make a front and back buffer
	buffA := make([]byte, MaxFooterSize)
	buffB := make([]byte, MaxFooterSize)
	sizeA := 0
	sizeB := 0
	h := sha512.New()
	var err error
	var stream io.Reader

	// If input is gzip then decompress it
	buf, err := pReader.Peek(2)
	if err != nil || len(buf) != 2 {
		return nil, nil, false, fmt.Errorf("failed to peek input: %w", err)
	} else {
		if buf[0] == 0x1f && buf[1] == 0x8b {
			var gzReader *gzip.Reader
			gzReader, err = gzip.NewReader(pReader)
			if err != nil {
				return nil, nil, false, fmt.Errorf("failed to create gzip reader: %w", err)
			}
			defer gzReader.Close()
			stream = gzReader
		} else {
			stream = pReader
		}
	}

	// Copy document, the signatures are in the last buffSize bytes
	for {
		sizeA, err = io.ReadFull(stream, buffA)
		if err != nil {
			if err == io.EOF || err == io.ErrUnexpectedEOF {
				// End of document cat buffers into one
				buffA = append(buffB[:sizeB], buffA[:sizeA]...)
				sizeA += sizeB
				break
			} else {
				return nil, nil, false, fmt.Errorf("error reading from stream: %w", err)
			}
		}

		// Write out B
		if sizeB > 0 {
			if _, writeErr := writer.Write(buffB[:sizeB]); writeErr != nil {
				return nil, nil, false, fmt.Errorf("failed to write: %w", writeErr)
			}
			if _, hashErr := h.Write(buffB[:sizeB]); hashErr != nil {
				return nil, nil, false, fmt.Errorf("failed to write: %w", hashErr)
			}
		}

		// Swap buffers
		buffA, buffB = buffB, buffA
		sizeB = sizeA
	}

	// buffA Contains the end of the document + delimiter + signatures
	index := bytes.LastIndex(buffA[:sizeA], []byte{'\n', '\n'})
	if index != -1 {

		// fmt.Println("Hash:", base64.RawStdEncoding.EncodeToString(h.Sum(nil)))
		// fmt.Println(string(buffA[index+2 : sizeA]))

		j := strings.Split(string(buffA[index+2:sizeA]), "\n")
		if strings.HasPrefix(j[0], FooterPrefix) {

			signatures := make(map[string]string, len(j))
			for _, line := range j[1:] {
				parts := strings.SplitN(line, ":", 2)
				if len(parts) == 2 && len(parts[0]) == FingerprintSize*4/3 {
					signatures[parts[0]] = parts[1]
				}
			}

			// Write out the last of the document
			if _, writeErr := writer.Write(buffA[:index]); writeErr != nil {
				return nil, nil, false, fmt.Errorf("failed to write to writer: %w", writeErr)
			}
			if _, hashErr := h.Write(buffA[:index]); hashErr != nil {
				return nil, nil, false, fmt.Errorf("failed to write to hash: %w", hashErr)
			}
			return h.Sum(nil), signatures, true, nil
		}
	}

	// No "sig-" section
	// just hash the document and return no signatures

	// Write out the last of the document
	if _, writeErr := writer.Write(buffA[:sizeA]); writeErr != nil {
		return nil, nil, false, fmt.Errorf("failed to write to writer: %w", writeErr)
	}
	if _, hashErr := h.Write(buffA[:sizeA]); hashErr != nil {
		return nil, nil, false, fmt.Errorf("failed to write to hash: %w", hashErr)
	}
	return h.Sum(nil), make(map[string]string), false, nil
}

// WriteSignatures writes a set of signatures to the provided writer in a specific format.
//
// Parameters:
//   - w io.Writer: The writer to which the signatures will be written.
//   - signatures map[string]string: A map of fingerprints to their corresponding signatures.
//
// Returns:
//   - error: An error if the write operation fails or if the signature section exceeds the maximum size.
func WriteSignatures(w io.Writer, signatures map[string]string) error {
	sigLen := 0

	// Write out delimiter + signatures
	s := []byte("\n\n" + FooterPrefix + "0.1\n")
	sigLen += len(s)
	if _, err := w.Write(s); err != nil {
		return fmt.Errorf("failed to write signature header: %w", err)
	}
	for fp, signature := range signatures {
		s := []byte(fp + ":" + signature + "\n")
		sigLen += len(s)
		if _, err := w.Write(s); err != nil {
			return fmt.Errorf("failed to write signature: %w", err)
		}
	}

	if sigLen >= MaxFooterSize {
		return fmt.Errorf("signature section exceeds maximum size")
	}

	return nil
}

func loadPriKeysFromFiles(files []string) ([]CryptoKey, error) {
	var result []CryptoKey
	for _, file := range files {
		if d, err := os.ReadFile(file); err != nil {
			return nil, err
		} else {
			if keys, err := loadPriKeys(d); err != nil {
				return nil, err
			} else {
				result = append(result, keys...)
			}
		}
	}
	return result, nil
}

func loadPriKeys(b []byte) ([]CryptoKey, error) {
	var result []CryptoKey
	var block *pem.Block
	for {
		block, b = pem.Decode(b)
		if block == nil {
			return result, nil
		}

		switch block.Type {
		case "PRIVATE KEY":
			if parsedKey, err := x509.ParsePKCS8PrivateKey(block.Bytes); err != nil {
				return nil, err
			} else {
				cryptoKey, err := NewCryptoKey(parsedKey)
				if err != nil {
					return nil, err
				}
				result = append(result, cryptoKey)
			}
		case "RSA PRIVATE KEY":
			if parsedKey, err := x509.ParsePKCS1PrivateKey(block.Bytes); err != nil {
				return nil, err
			} else {
				cryptoKey, err := NewCryptoKey(parsedKey)
				if err != nil {
					return nil, err
				}
				result = append(result, cryptoKey)
			}
		default:
			return nil, fmt.Errorf("key is of the wrong type")
		}
	}
}

func loadPubKeysFromFiles(files []string) ([]CryptoKey, error) {
	var result []CryptoKey
	for _, file := range files {
		if d, err := os.ReadFile(file); err != nil {
			return nil, fmt.Errorf("unable to read file: %s", file)
		} else {
			if keys, err := loadPubKeys(d); err != nil {
				return nil, err
			} else {
				result = append(result, keys...)
			}
		}
	}
	return result, nil
}

func loadPubKeys(b []byte) ([]CryptoKey, error) {
	var result []CryptoKey
	var block *pem.Block
	for {
		block, b = pem.Decode(b)
		if block == nil {
			return result, nil
		}

		switch block.Type {
		case "PRIVATE KEY":
			if parsedKey, err := x509.ParsePKCS8PrivateKey(block.Bytes); err != nil {
				return nil, err
			} else {
				cryptoKey, err := NewCryptoKey(parsedKey)
				if err != nil {
					return nil, err
				}
				result = append(result, cryptoKey)
			}
		case "PUBLIC KEY":
			if parsedKey, err := x509.ParsePKIXPublicKey(block.Bytes); err != nil {
				return nil, err
			} else {
				cryptoKey, err := NewCryptoKey(parsedKey)
				if err != nil {
					return nil, err
				}
				result = append(result, cryptoKey)
			}
		case "RSA PRIVATE KEY":
			if parsedKey, err := x509.ParsePKCS1PrivateKey(block.Bytes); err != nil {
				return nil, err
			} else {
				cryptoKey, err := NewCryptoKey(parsedKey)
				if err != nil {
					return nil, err
				}
				result = append(result, cryptoKey)
			}
		case "RSA PUBLIC KEY":
			if parsedKey, err := x509.ParsePKCS1PublicKey(block.Bytes); err != nil {
				return nil, err
			} else {
				cryptoKey, err := NewCryptoKey(parsedKey)
				if err != nil {
					return nil, err
				}
				result = append(result, cryptoKey)
			}
		default:
			return nil, fmt.Errorf("key is of the wrong type")
		}
	}
}

func openInput(file string, fp **os.File) (func() error, error) {
	if file == "-" {
		*fp = os.Stdin
		return func() error {
			return nil
		}, nil
	} else {
		var err error
		f, err := os.OpenFile(file, os.O_RDWR, 0666)
		if err != nil {
			return nil, err
		}
		*fp = f
		return func() error {
			return f.Close()
		}, nil
	}
}

func openTemp(fp **os.File) (func() error, error) {
	f, err := os.CreateTemp("", "*.tmp")
	if err != nil {
		return nil, err
	}
	*fp = f
	return func() error {
		f.Close()
		return os.Remove(f.Name())
	}, nil
}

func fetchWithETag(url, etagPath string) (*http.Response, error) {
	var fe *os.File

	if etagPath != "" {
		f, err := os.OpenFile(etagPath, os.O_RDWR|os.O_CREATE, 0660)
		if err != nil {
			return nil, fmt.Errorf("failed to open etag file: %w", err)
		}
		defer f.Close()
		fe = f
	}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	if fe != nil {
		content, err := io.ReadAll(fe)
		if err == nil {
			req.Header.Add("If-None-Match", string(content))
		}
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute request: %w", err)
	}

	if resp.StatusCode == http.StatusOK && fe != nil {
		newEtag := resp.Header.Get("Etag")
		if newEtag != "" {
			// Log the errors but don't fail the request
			if _, err := fe.Seek(0, 0); err != nil {
				fmt.Fprintf(os.Stderr, "Failed to seek ETag file: %v\n", err)
			} else if err := fe.Truncate(0); err != nil {
				fmt.Fprintf(os.Stderr, "Failed to truncate ETag file: %v\n", err)
			} else if _, err := fe.WriteString(newEtag); err != nil {
				fmt.Fprintf(os.Stderr, "Failed to write new ETag: %v\n", err)
			}
		}
	}

	return resp, nil
}

// CryptoKey is an interface that defines the operations for cryptographic keys.
// It provides methods for signing, verifying, generating fingerprints, and
// checking the privacy status of keys. This interface is designed to work with
// various cryptographic algorithms and key types, providing a unified way to
// handle cryptographic operations in the application.
type CryptoKey interface {
	// Sign creates a digital signature for the given SHA-512 hash using the private key.
	//
	// Parameters:
	//   - hash []byte: The pre-computed SHA-512 hash of the document to be signed.
	//
	// Returns:
	//   - string: A base64-encoded string representation of the signature.
	//   - error: Any error encountered during the signing process, or nil if successful.
	//            Returns an error if IsPrivate() is false, as signing requires a private key.
	Sign(hash []byte) (string, error)

	// Verify checks if a digital signature is valid for a given SHA-512 hash using the public key.
	//
	// Parameters:
	//   - hash []byte: The pre-computed SHA-512 hash of the document that was signed.
	//   - signature []byte: The digital signature to be verified.
	//
	// Returns:
	//   - error: An error if the verification fails, or nil if the signature is valid.
	Verify(hash []byte, signature []byte) error

	// Fingerprint generates a 20-character ASCII fingerprint for key.
	// It uses SHA-512 to hash the public key and returns the first 15 bytes (120 bits) encoded in base64.
	// This provides a compact, unique identifier for the key with a low probability of collisions.
	// With 120 bits, approximately 1.35e18 keys are needed for a 50% chance of collision.
	//
	// Returns:
	//   - string: A 20-character base64-encoded string representing the fingerprint.
	Fingerprint() string

	// IsPrivate checks if the key is a private key.
	//
	// Returns:
	//   - bool: true if the key is a private key, false if it's a public key.
	IsPrivate() bool
}

// NewCryptoKeyFromPEM creates a CryptoKey from a PEM block.
// It supports both private and public keys for Ed25519.
//
// Parameters:
//   - block *pem.Block: The PEM block containing the key data.
//
// Returns:
//   - CryptoKey: A new CryptoKey instance.
//   - error: Any error encountered during key parsing or creation.
func NewCryptoKeyFromPEM(block *pem.Block) (CryptoKey, error) {
	switch block.Type {
	case "PRIVATE KEY":
		privateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		return NewCryptoKey(privateKey)
	case "PUBLIC KEY":
		publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		return NewCryptoKey(publicKey)
	case "RSA PRIVATE KEY":
		privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		return NewCryptoKey(privateKey)
	case "RSA PUBLIC KEY":
		publicKey, err := x509.ParsePKCS1PublicKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		return NewCryptoKey(publicKey)
	default:
		return nil, fmt.Errorf("unsupported PEM block type: %s", block.Type)
	}
}

func NewCryptoKey(key any) (CryptoKey, error) {
	switch key := key.(type) {
	case ed25519.PrivateKey:
		return &ed25519Key{
			privateKey: key,
			publicKey:  key.Public().(ed25519.PublicKey),
			isPrivate:  true,
		}, nil
	case ed25519.PublicKey:
		return &ed25519Key{
			publicKey: key,
			isPrivate: false,
		}, nil
	/*
		case *rsa.PrivateKey:
			return &rsaKey{
				privateKey: key,
				publicKey:  &key.PublicKey,
			}, nil
		case *rsa.PublicKey:
			return &rsaKey{
				publicKey: key,
			}, nil
	*/
	default:
		return nil, fmt.Errorf("unsupported key type")
	}
}

type ed25519Key struct {
	CryptoKey
	privateKey ed25519.PrivateKey
	publicKey  ed25519.PublicKey
	isPrivate  bool
}

func (this *ed25519Key) Sign(hash []byte) (string, error) {
	if !this.isPrivate {
		return "", fmt.Errorf("cannot sign: no private key available")
	}
	signature, err := this.privateKey.Sign(nil, hash, &ed25519.Options{Hash: crypto.SHA512})
	if err != nil {
		return "", err
	}
	return base64.RawStdEncoding.EncodeToString(signature), nil
}

func (this *ed25519Key) Verify(hash []byte, signature []byte) error {
	if this.publicKey == nil {
		return fmt.Errorf("cannot verify: no public key available")
	}
	if err := ed25519.VerifyWithOptions(this.publicKey, hash, signature, &ed25519.Options{Hash: crypto.SHA512}); err != nil {
		return err
	}
	return nil
}

func (this *ed25519Key) Fingerprint() string {
	if this.publicKey == nil {
		return ""
	}
	b, _ := x509.MarshalPKIXPublicKey(this.publicKey)
	h := sha512.New()
	h.Write([]byte(b))
	return base64.RawStdEncoding.EncodeToString(h.Sum(nil)[0:FingerprintSize])
}

func (this *ed25519Key) IsPrivate() bool {
	return this.isPrivate
}

/*
type rsaKey struct {
	CryptoKey
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
}

func (this *rsaKey) Sign(hash []byte) (string, error) {
	if this.privateKey == nil {
		return "", fmt.Errorf("cannot sign: no private key available")
	}
	signature, err := rsa.SignPKCS1v15(nil, this.privateKey, crypto.SHA512, hash)
	if err != nil {
		return "", err
	}
	return base64.RawStdEncoding.EncodeToString(signature), nil
}

func (this *rsaKey) Verify(hash []byte, signature []byte) error {
	if this.publicKey == nil {
		return fmt.Errorf("cannot verify: no public key available")
	}
	return rsa.VerifyPKCS1v15(this.publicKey, crypto.SHA512, hash, signature)
}

func (this *rsaKey) Fingerprint() string {
	h := sha512.New()
	h.Write(x509.MarshalPKCS1PublicKey(this.publicKey))
	return base64.RawStdEncoding.EncodeToString(h.Sum(nil)[0:FingerprintLength])
}

func (this *rsaKey) IsPrivate() bool {
	return this.privateKey != nil
}
*/
