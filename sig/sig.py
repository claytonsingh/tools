import argparse
import base64
import gzip
import hashlib
import io
import requests
import shutil
import sys
import tempfile
from contextlib import ExitStack
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import asymmetric, hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from cryptography.hazmat.primitives.asymmetric.mldsa import (
    MLDSA44PrivateKey,
    MLDSA44PublicKey,
    MLDSA65PrivateKey,
    MLDSA65PublicKey,
    MLDSA87PrivateKey,
    MLDSA87PublicKey,
)

HEADER_PREFIX = "sig-"
HEADER_VERSION = "0.1"
MAX_HEADER_SIZE = 1024 * 128
FINGERPRINT_SIZE = 15  # 15 bytes = 120 bits

PRIVATE_KEY_TYPES = (
    asymmetric.ed25519.Ed25519PrivateKey,
    asymmetric.rsa.RSAPrivateKey,
    MLDSA44PrivateKey,
    MLDSA65PrivateKey,
    MLDSA87PrivateKey,
)
PUBLIC_KEY_TYPES = (
    asymmetric.ed25519.Ed25519PublicKey,
    asymmetric.rsa.RSAPublicKey,
    MLDSA44PublicKey,
    MLDSA65PublicKey,
    MLDSA87PublicKey,
)

def b64encode(b):
    """
    Encodes bytes using base64 raw encoding into a UTF-8 encoded string.
    """
    return base64.b64encode(b).replace(b'=', b'').decode('utf-8')

def b64decode(s):
    """
    Decodes a base64 raw encoded string into bytes.
    """
    return base64.b64decode(s + "===")

class NullWriter:
    def write(self, s): pass

class ChunkReader(io.RawIOBase):
    """
    Presents an iterator of byte chunks as a readable stream.

    A streamed response body is only exposed as an iterator. Its underlying
    raw stream closes itself once the body has been consumed, which the gzip
    reader cannot tolerate: it reads the trailer after the last chunk and
    would see a closed file rather than end of stream. Iterating also applies
    any Content-Encoding the server used, which reading the raw stream does
    not.
    """

    def __init__(self, chunks):
        self.chunks = iter(chunks)
        self.pending = b''

    def readable(self):
        return True

    def readinto(self, target):
        while not self.pending:
            try:
                self.pending = next(self.chunks)
            except StopIteration:
                return 0
        size = min(len(target), len(self.pending))
        target[:size] = self.pending[:size]
        self.pending = self.pending[size:]
        return size

class TeeReader():
    def __init__(self, reader, writer):
        self.reader = reader
        self.writer = writer

    def read(self, size=-1):
        data = self.reader.read(size)
        self.writer.write(data)
        return data

    def readinto(self, b):
        n = self.reader.readinto(b)
        self.writer.write(b[:n])
        return n

    def readable(self):
        return self.reader.readable()

    def peek(self, size=-1):
        return self.reader.peek(size)

    @property
    def closed(self):
        return self.reader.closed

class CryptoKey:
    def __init__(self, key):
        self.private_key = None
        self.public_key = None
        self.is_private = False

        if isinstance(key, PRIVATE_KEY_TYPES):
            self.private_key = key
            self.public_key = key.public_key()
            self.is_private = True
        elif isinstance(key, PUBLIC_KEY_TYPES):
            self.public_key = key
        else:
            raise ValueError("Unsupported key type")

    def sign(self, hash_bytes):
        if not self.is_private:
            raise ValueError("Cannot sign: no private key available")
        if isinstance(self.private_key, asymmetric.rsa.RSAPrivateKey):
            signature = self.private_key.sign(hash_bytes, padding.PKCS1v15(), Prehashed(hashes.SHA512()))
        else:
            signature = self.private_key.sign(hash_bytes)
        return b64encode(signature)

    def verify(self, hash_bytes, signature):
        if not self.public_key:
            raise ValueError("Cannot verify: no public key available")
        try:
            if isinstance(self.public_key, asymmetric.rsa.RSAPublicKey):
                self.public_key.verify(signature, hash_bytes, padding.PKCS1v15(), Prehashed(hashes.SHA512()))
            else:
                self.public_key.verify(signature, hash_bytes)
            return True
        except:
            return False

    def fingerprint(self):
        if not self.public_key:
            raise ValueError("Cannot fingerprint: no public key available")
        key_bytes = self.public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        hash_obj = hashlib.sha512(key_bytes)
        return b64encode(hash_obj.digest()[:FINGERPRINT_SIZE])

def binary_stream(stream):
    buf = getattr(stream, "buffer", None)
    if buf is not None:
        return buf
    return stream

def iter_pem_blocks(data):
    begin_marker = b"-----BEGIN "
    end_marker = b"-----END "
    pos = 0
    while True:
        begin = data.find(begin_marker, pos)
        if begin < 0:
            return
        end_label = data.find(end_marker, begin)
        if end_label < 0:
            return
        end = data.find(b"-----", end_label + len(end_marker))
        if end < 0:
            return
        end += 5
        yield data[begin:end]
        pos = end

def load_keys(file_path, private_only=False):
    with open(file_path, 'rb') as key_file:
        pem_data = key_file.read()

    keys = []
    for block in iter_pem_blocks(pem_data):
        try:
            private_key = serialization.load_pem_private_key(block, password=None)
            keys.append(CryptoKey(private_key))
            continue
        except Exception:
            pass
        if private_only:
            # Signing needs a private key, so a public key or a certificate
            # in the file is an error rather than a block to skip over
            raise ValueError("Key is of the wrong type")
        try:
            public_key = serialization.load_pem_public_key(block)
            keys.append(CryptoKey(public_key))
            continue
        except Exception:
            raise ValueError("Invalid key file")

    # A file with no PEM blocks yields no keys and no error. Callers decide
    # what that means: fingerprint reports nothing, verify finds no match
    return keys

def unpack_document(reader, writer):
    """
    Reads and unpacks a document from the provided reader, writes the content to the writer,
    and extracts any signatures present. Supports both gzipped and non-gzipped input.

    Args:
    reader (io.IOBase): The source from which to read the document.
    writer (io.IOBase): The destination to write the unpacked document content.

    Returns:
    tuple: (hash_value, signatures)
        hash_value (bytes): The SHA-512 hash of the document content.
        signatures (dict): A dictionary of fingerprints and their corresponding signatures if present, otherwise None.
    """

    reader = io.BufferedReader(reader)
    
    # Check if input is gzipped. A document shorter than the magic cannot be
    # gzip, so a short peek falls through to the plain stream path rather than
    # being an error
    peek_buffer = reader.peek(2)[:2]

    if peek_buffer == b'\x1f\x8b':
        stream = io.BufferedReader(gzip.GzipFile(fileobj=reader))
    else:
        stream = reader

    footer_bytes = HEADER_PREFIX.encode('utf-8')
    hasSignatures = stream.peek(len(footer_bytes))[:len(footer_bytes)] == footer_bytes

    headers = {}
    signature_section_size = 1

    if hasSignatures:
        # Read the version line and refuse formats we do not understand, so
        # that a future incompatible version is rejected rather than misread
        # as this one
        line = stream.readline()
        if not line:
            raise ValueError("Failed to read HeaderPrefix line")
        version = line[len(footer_bytes):].rstrip(b'\n').decode('utf-8')
        if version != HEADER_VERSION:
            raise ValueError("Unsupported format version '{0}', expected '{1}'".format(version, HEADER_VERSION))
        signature_section_size += len(line) + 1  # +1 for the newline character

        # Read signatures
        while True:
            # Remove newline character
            line = stream.readline()[:-1]
            if not line:
                break  # Empty line indicates end of signatures
            signature_section_size += len(line) + 1  # +1 for the newline character
            if signature_section_size >= MAX_HEADER_SIZE:
                raise ValueError("Signature section exceeds maximum size")
            parts = line.decode('utf-8').split(":", 1)
            if len(parts) == 2:
                headers[parts[0]] = parts[1]

    # Read and hash document content
    h = hashlib.sha512()
    while True:
        chunk = stream.read(8192)  # Read in 8KB chunks
        if not chunk:
            break
        writer.write(chunk)
        h.update(chunk)
    expected_hash = h.digest()

    if hasSignatures:
        # Check for a header named "!hash-sha512" and compare that to expected_hash
        if "!hash-sha512" not in headers:
            raise ValueError("Missing hash header")
        
        decoded_hash = b64decode(headers["!hash-sha512"])
        if decoded_hash != expected_hash:
            raise ValueError("Hash mismatch: expected {}, got {}".format(b64encode(expected_hash), b64encode(decoded_hash)))

    return expected_hash, headers if hasSignatures else None

def write_signatures(writer, headers):
    """
    Writes a set of signatures to the provided writer in a specific format.

    Args:
    writer (io.IOBase): The writer to which the signatures will be written.
    headers (dict): A dictionary of fingerprints to their corresponding signatures.

    Returns:
    None

    Raises:
    ValueError: If the signature section exceeds the maximum size.
    """
    sig_len = 1

    # Write out delimiter + signatures
    line = "{0}{1}\n".format(HEADER_PREFIX, HEADER_VERSION).encode('utf-8')
    sig_len += len(line)
    writer.write(line)

    # Write signatures in key order, matching WriteHeader in sig.go, so that
    # both implementations emit the same document for the same input
    for key, val in sorted(headers.items()):
        if ':' in key or '\n' in key or ':' in val or '\n' in val:
            raise ValueError("Invalid characters in header: {}: {}".format(key, val))
        line = "{}:{}\n".format(key, val).encode('utf-8')
        sig_len += len(line)
        writer.write(line)

    if sig_len >= MAX_HEADER_SIZE:
        raise ValueError("Signature section exceeds maximum size")
    
    writer.write(b'\n')

def cmd_sign(args):
    try:
        # Open input file, for writing as well only when signing in place
        with ExitStack() as stack:
            input_mode = 'r+b' if args.output_file == args.input_file else 'rb'
            input_file = binary_stream(sys.stdin) if args.input_file == '-' else stack.enter_context(open(args.input_file, input_mode))
            temp_file = stack.enter_context(tempfile.TemporaryFile(mode='w+b'))

            # Load private keys
            keys = []
            for key_file in args.keys:
                keys.extend(load_keys(key_file, private_only=True))

            hash_value, headers = unpack_document(TeeReader(input_file, temp_file), NullWriter())
            if headers is None:
                headers = {}
            headers["!hash-sha512"] = b64encode(hash_value)

            # Sign with each key
            for key in keys:
                if key.is_private:
                    fingerprint = key.fingerprint()
                    signature = key.sign(hash_value)
                    headers[fingerprint] = signature

            if hasattr(temp_file, 'sync'):
                temp_file.sync()
            temp_file.seek(0)

            # Check the header against a throwaway writer before the output is
            # opened, so an oversized or malformed header cannot leave a
            # partial file behind
            write_signatures(NullWriter(), headers)

            # Write out content
            if args.output_file == '-':
                gzip_writer = stack.enter_context(gzip.GzipFile(filename="", mode="wb", mtime=0, fileobj=binary_stream(sys.stdout)))
            elif args.output_file == args.input_file:
                input_file.seek(0)
                input_file.truncate()
                gzip_writer = stack.enter_context(gzip.GzipFile(filename="", mode="wb", mtime=0, fileobj=input_file))
            else:
                output_file = stack.enter_context(open(args.output_file, 'wb'))
                gzip_writer = stack.enter_context(gzip.GzipFile(filename="", mode="wb", mtime=0, fileobj=output_file))
            write_signatures(gzip_writer, headers)
            unpack_document(temp_file, gzip_writer)
        print("Document signed successfully", file=sys.stderr)
        return 0
    
    except Exception as e:
        print("Error in sign command: {}".format(e), file=sys.stderr)
        return 1

def cmd_verify(args):
    keys = []
    for key_file in args.keys:
        try:
            keys.extend(load_keys(key_file))
        except Exception as e:
            print("Error loading key from {}: {}".format(key_file, e), file=sys.stderr)
            return 1

    try:
        with ExitStack() as stack:
            # Open input and temporary file. The output is deliberately not
            # opened yet, see below
            input_file = binary_stream(sys.stdin) if args.input_file == '-' else stack.enter_context(open(args.input_file, 'rb'))
            temp_file = stack.enter_context(tempfile.TemporaryFile(mode='w+b'))

            hash_value, signatures = unpack_document(input_file, temp_file)

            if signatures is None:
                print("No signatures found", file=sys.stderr)
                return 1

            for key in keys:
                fingerprint = key.fingerprint()
                print(fingerprint, file=sys.stderr)
                if fingerprint in signatures:
                    signature = b64decode(signatures[fingerprint])
                    if key.verify(hash_value, signature):
                        print("Valid signature from key with fingerprint: {}".format(fingerprint), file=sys.stderr)
                        break
                    else:
                        print("Invalid signature from key with fingerprint: {}".format(fingerprint), file=sys.stderr)
            else:
                print("No valid signatures found", file=sys.stderr)
                return 1

            # Seek to the beginning of the temporary file
            temp_file.seek(0)

            # Only now open the output. Opening it any earlier would create,
            # and truncate, a file that a failed verification should leave
            # untouched. This also makes verifying in place work, since the
            # input has already been read in full
            output_file = binary_stream(sys.stdout) if args.output_file == '-' else stack.enter_context(open(args.output_file, 'wb'))

            # Copy the temporary file to the output file
            shutil.copyfileobj(temp_file, output_file, 8192)  # Copy in 8KB chunks

            print("Document verified successfully", file=sys.stderr)
            return 0

    except Exception as e:
        print("Error during verification: {}".format(e), file=sys.stderr)
        return 1

def cmd_inspect(args):
    try:
        with ExitStack() as stack:
            input_file = binary_stream(sys.stdin) if args.input_file == '-' else stack.enter_context(open(args.input_file, 'rb'))
            
            _, headers = unpack_document(input_file, NullWriter())

            # An unsigned document is valid input, it simply has no headers to
            # report, so there is nothing to print and nothing to fail on
            if headers is None:
                headers = {}

            max_len = max((len(key) for key in headers.keys()), default=0)
            # Sort the headers
            for key, val in sorted(headers.items()):
                print("{:<{}} {}".format(key, max_len, val))
            
            return 0
    except Exception as e:
        print("Error during inspection: {}".format(e), file=sys.stderr)
        return 1

def cmd_fingerprint(args):
    try:
        for file in args.keys:
            for key in load_keys(file):
                print("{} {}".format(key.fingerprint(), file))
    except Exception as e:
        print("Error processing file {}: {}".format(file, e), file=sys.stderr)
        return 1
    return 0

def cmd_fetch(args):
    try:
        # Load public keys for verification
        keys = []
        for key_file in args.keys:
            try:
                keys.extend(load_keys(key_file))
            except Exception as e:
                print("Error loading key from {}: {}".format(key_file, e), file=sys.stderr)
                return 1

        with ExitStack() as stack:
            headers = {}
            # Prepare ETag file handling
            etag_file = None
            if args.etag:
                try:
                    etag_file = stack.enter_context(open(args.etag, 'r+'))
                    etag = etag_file.read().strip()
                    headers.update({'If-None-Match': etag} if etag else {})
                except FileNotFoundError:
                    etag_file = stack.enter_context(open(args.etag, 'w+'))

            # Fetch the content
            response = stack.enter_context(requests.get(args.url, headers=headers, stream=True))

            if response.status_code == 304:
                print("Content not modified", file=sys.stderr)
                return 3

            if response.status_code != 200:
                print("Unexpected status code: {}".format(response.status_code), file=sys.stderr)
                return 1

            # Record the new ETag as soon as the response is accepted. It
            # describes what the server served, not whether the document
            # turned out to be one we trust
            if etag_file and 'ETag' in response.headers:
                etag_file.seek(0)
                etag_file.write(response.headers['ETag'])
                etag_file.truncate()

            # Verify and unpack the document
            temp_file = stack.enter_context(tempfile.TemporaryFile(mode='w+b'))
            hash_value, signatures = unpack_document(ChunkReader(response.iter_content(8192)), temp_file)

            if signatures is None:
                print("No signatures found", file=sys.stderr)
                return 1

            for key in keys:
                fingerprint = key.fingerprint()
                if fingerprint in signatures:
                    signature = b64decode(signatures[fingerprint])
                    if key.verify(hash_value, signature):
                        print("Valid signature from key with fingerprint: {}".format(fingerprint), file=sys.stderr)
                        break
                    else:
                        print("Invalid signature from key with fingerprint: {}".format(fingerprint), file=sys.stderr)
            else:
                print("No valid signatures found", file=sys.stderr)
                return 1

            # Write the content to the output file
            temp_file.seek(0)
            output_file = binary_stream(sys.stdout) if args.output_file == '-' else stack.enter_context(open(args.output_file, 'wb'))
            shutil.copyfileobj(temp_file, output_file)

        print("Document fetched and verified successfully", file=sys.stderr)
        return 0

    except Exception as e:
        print("Error during fetch: {}".format(e), file=sys.stderr)
        return 1

def main(args=None):
    # Emit bare newlines on every platform. Python would otherwise translate
    # them to CRLF on Windows, which puts the text output of inspect and
    # fingerprint out of step with the rest of the tooling
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(newline="\n")

    parser = argparse.ArgumentParser(description="Signature tool for signing, verifying, inspecting, and fetching documents with cryptographic signatures.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Sign command
    sign_parser = subparsers.add_parser("sign", help="Sign a document using provided key files.")
    sign_parser.add_argument("--if", dest="input_file", default="-", help="Path to the input file to be signed (default: stdin).")
    sign_parser.add_argument("--of", dest="output_file", default="-", help="Path to the output file where the signed document will be saved (default: stdout).")
    sign_parser.add_argument("keys", nargs="+", help="Paths to private key files used for signing the document.")

    # Verify command
    verify_parser = subparsers.add_parser("verify", help="Verify the signature of a document using provided key files.")
    verify_parser.add_argument("--if", dest="input_file", default="-", help="Path to the input file to be verified (default: stdin).")
    verify_parser.add_argument("--of", dest="output_file", default="-", help="Path to the output file where the verified document will be saved (default: stdout).")
    verify_parser.add_argument("keys", nargs="+", help="Paths to public or private key files used for verifying the document's signature.")

    # Inspect command
    inspect_parser = subparsers.add_parser("inspect", help="Inspect a document to extract and display its signatures.")
    inspect_parser.add_argument("--if", dest="input_file", default="-", help="Path to the input file to be inspected (default: stdin).")

    # Fingerprint command
    fingerprint_parser = subparsers.add_parser("fingerprint", help="Generate and display the fingerprint of provided key files.")
    fingerprint_parser.add_argument("keys", nargs="+", help="Paths to public or private key files for which the fingerprint will be generated.")

    # Fetch command
    fetch_parser = subparsers.add_parser("fetch", help="Fetch a document from a URL and verify its signature using provided key files.")
    fetch_parser.add_argument("--etag", help="Path to the file where the ETag will be checked and stored.")
    fetch_parser.add_argument("--of", dest="output_file", default="-", help="Path to the output file where the fetched document will be saved (default: stdout).")
    fetch_parser.add_argument("url", help="URL of the document to be fetched.")
    fetch_parser.add_argument("keys", nargs="+", help="Paths to public/private key files used for verifying the fetched document's signature.")

    args = parser.parse_args(args)

    if args.command == "sign":
        return cmd_sign(args)
    elif args.command == "verify":
        return cmd_verify(args)
    elif args.command == "inspect":
        return cmd_inspect(args)
    elif args.command == "fingerprint":
        return cmd_fingerprint(args)
    elif args.command == "fetch":
        return cmd_fetch(args)

if __name__ == "__main__":
    sys.exit(main())
