package main

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func decompressGzip(data []byte) ([]byte, error) {
	gzipReader, err := gzip.NewReader(bytes.NewBuffer(data))
	if err != nil {
		return nil, err
	}
	defer gzipReader.Close()

	var result bytes.Buffer
	_, err = io.Copy(&result, gzipReader)
	if err != nil {
		return nil, err
	}

	return result.Bytes(), nil
}

func TestSigCli(t *testing.T) {
	// Create a temporary directory for test files
	tempDir, err := os.MkdirTemp("", "sig_test")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	testDir := "./test"
	files := map[string]string{
		"ed25519_1_key":   filepath.Join(testDir, "ed25519_1_key.pem"),
		"ed25519_1_pub":   filepath.Join(testDir, "ed25519_1_pub.pem"),
		"ed25519_2_key":   filepath.Join(testDir, "ed25519_2_key.pem"),
		"ed25519_2_pub":   filepath.Join(testDir, "ed25519_2_pub.pem"),
		"ed25519_3_key":   filepath.Join(testDir, "ed25519_3_key.pem"),
		"ed25519_3_pub":   filepath.Join(testDir, "ed25519_3_pub.pem"),
		"test.txt":        filepath.Join(testDir, "test.txt"),
		"test.txt.sig":    filepath.Join(testDir, "test.txt.sig"),
		"test.txt.sig.gz": filepath.Join(testDir, "test.txt.sig.gz"),
	}

	// Test cases
	testCases := []struct {
		name     string
		args     []string
		stdin    string
		wantExit int
		checkOut func(t *testing.T, out []byte)
	}{
		{
			name:     "Fingerprint Public Key",
			args:     []string{"fingerprint", files["ed25519_1_pub"]},
			wantExit: 0,
			checkOut: func(t *testing.T, out []byte) {
				expected := "cQBQY+x1KQrCLDeTOkrN " + files["ed25519_1_pub"] + "\n"
				if !bytes.Equal(out, []byte(expected)) {
					t.Errorf("Expected output to equal %q, got: %q", expected, out)
				}
			},
		},
		{
			name:     "Fingerprint Private Key",
			args:     []string{"fingerprint", files["ed25519_1_key"]},
			wantExit: 0,
			checkOut: func(t *testing.T, out []byte) {
				expected := "cQBQY+x1KQrCLDeTOkrN " + files["ed25519_1_key"] + "\n"
				if !bytes.Equal(out, []byte(expected)) {
					t.Errorf("Expected output to equal %q, got: %q", expected, out)
				}
			},
		},
		{
			name:     "Fingerprint Multiple Keys",
			args:     []string{"fingerprint", files["ed25519_1_key"], files["ed25519_1_pub"], files["ed25519_2_key"], files["ed25519_2_pub"], files["ed25519_3_key"], files["ed25519_3_pub"]},
			wantExit: 0,
			checkOut: func(t *testing.T, out []byte) {
				expected := "cQBQY+x1KQrCLDeTOkrN " + files["ed25519_1_key"] + "\n" +
					"cQBQY+x1KQrCLDeTOkrN " + files["ed25519_1_pub"] + "\n" +
					"LRl25NJe/9nhV7ndcoHH " + files["ed25519_2_key"] + "\n" +
					"LRl25NJe/9nhV7ndcoHH " + files["ed25519_2_pub"] + "\n" +
					"cQBQY+x1KQrCLDeTOkrN " + files["ed25519_3_key"] + "\n" +
					"LRl25NJe/9nhV7ndcoHH " + files["ed25519_3_key"] + "\n" +
					"cQBQY+x1KQrCLDeTOkrN " + files["ed25519_3_pub"] + "\n" +
					"LRl25NJe/9nhV7ndcoHH " + files["ed25519_3_pub"] + "\n"
				if !bytes.Equal(out, []byte(expected)) {
					t.Errorf("Expected output to equal %q, got: %q", expected, out)
				}
			},
		},
		{
			name:     "Sign",
			args:     []string{"sign", "--if", files["test.txt"], "--of", filepath.Join(tempDir, "test.txt.sig.gz"), files["ed25519_1_key"]},
			wantExit: 0,
			checkOut: func(t *testing.T, out []byte) {
				// Check if the signed file was created
				signedFile := filepath.Join(tempDir, "test.txt.sig.gz")
				if _, err := os.Stat(signedFile); os.IsNotExist(err) {
					t.Errorf("Signed file was not created")
				}

				// Check if the signed file is byte identical to the expected file
				expectedFile := filepath.Join(testDir, "test.txt.sig")
				expectedBytes, err := os.ReadFile(expectedFile)
				if err != nil {
					t.Fatalf("Failed to read expected file: %v", err)
				}
				signedBytes, err := os.ReadFile(signedFile)
				if err != nil {
					t.Fatalf("Failed to read signed file: %v", err)
				}

				// Decompress the signed bytes
				decompressedSignedBytes, err := decompressGzip(signedBytes)
				if err != nil {
					t.Fatalf("Failed to decompress signed file: %v", err)
				}

				if !bytes.Equal(decompressedSignedBytes, expectedBytes) {
					t.Errorf("Signed file content does not match expected content")
				}
			},
		},
		{
			name:     "Inspect Uncompressed",
			args:     []string{"inspect", "--if", filepath.Join(testDir, "test.txt.sig")},
			wantExit: 0,
			checkOut: func(t *testing.T, out []byte) {
				expected := "!hash-sha512         kiwVVPAbYunE5r2ULyxcRXJ9Ngg6H4cewJzAjLBjEpjvXeXMEdkv0nTLHNKItKWyNgE3mVvlyeElVCsYOJjJBQ\ncQBQY+x1KQrCLDeTOkrN lz4P8GZ9CEONNlTvBMMKp8yIZdrqgrLE4dlhdkNXfwlECRv7M5CSJ6/rtoUm88+ZALREv2QyPkjHythyByWhDQ\n"
				if !bytes.Equal(out, []byte(expected)) {
					t.Errorf("Expected output to equal %q, got: %q", expected, out)
				}
			},
		},
		{
			name:     "Inspect Compressed",
			args:     []string{"inspect", "--if", filepath.Join(testDir, "test.txt.sig.gz")},
			wantExit: 0,
			checkOut: func(t *testing.T, out []byte) {
				expected := "!hash-sha512         kiwVVPAbYunE5r2ULyxcRXJ9Ngg6H4cewJzAjLBjEpjvXeXMEdkv0nTLHNKItKWyNgE3mVvlyeElVCsYOJjJBQ\ncQBQY+x1KQrCLDeTOkrN lz4P8GZ9CEONNlTvBMMKp8yIZdrqgrLE4dlhdkNXfwlECRv7M5CSJ6/rtoUm88+ZALREv2QyPkjHythyByWhDQ\n"
				if !bytes.Equal(out, []byte(expected)) {
					t.Errorf("Expected output to equal %q, got: %q", expected, out)
				}
			},
		},
		{
			name:     "Verify Correct Public Key",
			args:     []string{"verify", "--if", filepath.Join(testDir, "test.txt.sig"), "--of", filepath.Join(tempDir, "test.txt"), files["ed25519_1_pub"]},
			wantExit: 0,
			checkOut: func(t *testing.T, out []byte) {
				// Read the expected file content
				expectedBytes, err := os.ReadFile(files["test.txt"])
				if err != nil {
					t.Fatalf("Failed to read expected file: %v", err)
				}

				// Read the public key file content
				documentBytes, err := os.ReadFile(filepath.Join(tempDir, "test.txt"))
				if err != nil {
					t.Fatalf("Failed to read public key file: %v", err)
				}

				// Compare the output with the public key file content
				if !bytes.Equal(expectedBytes, documentBytes) {
					t.Errorf("Output does not match expected content. Expected: %q, got: %q", documentBytes, expectedBytes)
				}
			},
		},
		{
			name:     "Verify Correct Private Key",
			args:     []string{"verify", "--if", filepath.Join(testDir, "test.txt.sig"), "--of", filepath.Join(tempDir, "test.txt"), files["ed25519_1_key"]},
			wantExit: 0,
			checkOut: func(t *testing.T, out []byte) {
				// Read the expected file content
				expectedBytes, err := os.ReadFile(files["test.txt"])
				if err != nil {
					t.Fatalf("Failed to read expected file: %v", err)
				}

				// Read the public key file content
				documentBytes, err := os.ReadFile(filepath.Join(tempDir, "test.txt"))
				if err != nil {
					t.Fatalf("Failed to read public key file: %v", err)
				}

				// Compare the output with the public key file content
				if !bytes.Equal(expectedBytes, documentBytes) {
					t.Errorf("Output does not match expected content. Expected: %q, got: %q", documentBytes, expectedBytes)
				}
			},
		},
		{
			name:     "Verify Incorrect Public Key",
			args:     []string{"verify", "--if", filepath.Join(testDir, "test.txt.sig"), "--of", filepath.Join(tempDir, "test-verify-incorrect-pub.txt"), files["ed25519_2_pub"]},
			wantExit: 1,
			checkOut: func(t *testing.T, out []byte) {
				if f, err := os.Stat(filepath.Join(tempDir, "test-verify-incorrect-pub.txt")); err == nil {
					fmt.Println("File exists:", f)
					t.Errorf("File %s should not exist", filepath.Join(tempDir, "test.txt"))
				} else if !os.IsNotExist(err) {
					t.Fatalf("Failed to check if file exists: %v", err)
				}
			},
		},
		{
			name:     "Verify Unsigned",
			args:     []string{"verify", "--if", filepath.Join(testDir, "test.txt"), "--of", filepath.Join(tempDir, "test-verify-unsigned.txt"), files["ed25519_1_pub"]},
			wantExit: 1,
			checkOut: func(t *testing.T, out []byte) {
				if f, err := os.Stat(filepath.Join(tempDir, "test-verify-incorrect-pub.txt")); err == nil {
					fmt.Println("File exists:", f)
					t.Errorf("File %s should not exist", filepath.Join(tempDir, "test.txt"))
				} else if !os.IsNotExist(err) {
					t.Fatalf("Failed to check if file exists: %v", err)
				}
			},
		},
		{
			name:     "Fetch Correct Public Key",
			args:     []string{"fetch", "https://github.com/claytonsingh/tools/raw/refs/heads/master/sig/test/test.txt.sig.gz", "--of", filepath.Join(tempDir, "remote_fetched.txt"), files["ed25519_1_pub"]},
			wantExit: 0,
			checkOut: func(t *testing.T, out []byte) {
				// Read the expected file content
				expectedBytes, err := os.ReadFile(files["test.txt"])
				if err != nil {
					t.Fatalf("Failed to read expected file: %v", err)
				}

				// Read the fetched file content
				fetchedBytes, err := os.ReadFile(filepath.Join(tempDir, "remote_fetched.txt"))
				if err != nil {
					t.Fatalf("Failed to read fetched file: %v", err)
				}

				// Compare the fetched content with the expected content
				if !bytes.Equal(expectedBytes, fetchedBytes) {
					t.Errorf("Fetched content does not match expected content. Expected: %q, got: %q", expectedBytes, fetchedBytes)
				}
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Capture stdout
			oldStdout := os.Stdout
			r, w, _ := os.Pipe()
			os.Stdout = w

			// Capture stdin if needed
			oldStdin := os.Stdin
			if tc.stdin != "" {
				stdinR, stdinW, _ := os.Pipe()
				os.Stdin = stdinR
				go func() {
					defer stdinW.Close()
					io.WriteString(stdinW, tc.stdin)
				}()
			}

			// Use a WaitGroup to synchronize the goroutine
			var wg sync.WaitGroup
			wg.Add(1)

			// Create a buffer to store the output
			var buf bytes.Buffer

			// Start a goroutine to read from the pipe
			go func() {
				defer wg.Done()
				io.Copy(&buf, r)
			}()

			// Run the command and check the exit code
			exitCode := run(tc.args)
			if exitCode != tc.wantExit {
				t.Errorf("Expected exit code %d, got %d", tc.wantExit, exitCode)
			}

			// Close the write end of the pipe
			w.Close()

			// Wait for the goroutine to finish reading
			wg.Wait()

			// Restore stdout and stdin
			os.Stdout = oldStdout
			os.Stdin = oldStdin

			// Get the captured output
			out := buf.Bytes()

			// Check output
			if tc.checkOut != nil {
				tc.checkOut(t, out)
			}
		})
	}
}
