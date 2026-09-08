package main

// Conformance harness. The test plan lives in test/cases/*.json and is shared
// with the Python implementation, which runs the same plan from cli_test.py.
// See test/cases/README.md for the schema.
//
// The contract being checked is exit code, stdout and the files left in the
// working directory. Stderr is deliberately not part of it, because the two
// implementations word their diagnostics differently, so it is not a target a
// case can assert on at all. It is captured only to report a wrong exit code.
//
// Every content assertion is an exact match against a reference, either a file
// under test or inline text. Two wildcard tokens cover the only nondeterminism
// in the suite: {b64:N} for a randomized signature and {any} for a server
// chosen value.

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// Stream targets. Anything else names a path relative to the working directory.
const (
	targetStdout = "stdout"
	targetStdin  = "stdin"
)

// sigBinary is the path to the binary under test, built once by TestMain.
// fixtureDir is the committed test directory and is only ever read. Both are
// absolute, because a group runs with the working directory moved elsewhere.
var (
	sigBinary  string
	fixtureDir string
)

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "sig_bin")
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create build directory: %v\n", err)
		os.Exit(1)
	}
	fixtureDir, err = filepath.Abs("test")
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to resolve test directory: %v\n", err)
		os.Exit(1)
	}
	sigBinary = filepath.Join(dir, "sig")
	if runtime.GOOS == "windows" {
		sigBinary += ".exe"
	}
	// The cases run the tool as a child process, so `go test -cover` sees
	// nothing of it. Setting GOCOVERDIR builds an instrumented binary instead,
	// and every case then writes its counters there for `go tool covdata`.
	buildArgs := []string{"build", "-o", sigBinary, "."}
	if coverDir := os.Getenv("GOCOVERDIR"); coverDir != "" {
		// A case runs with the working directory moved into a copy that is
		// about to be deleted, and the child inherits the variable, so it has
		// to name a place that outlives the run.
		abs, err := filepath.Abs(coverDir)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to resolve GOCOVERDIR: %v\n", err)
			os.Exit(1)
		}
		os.Setenv("GOCOVERDIR", abs)
		buildArgs = []string{"build", "-cover", "-o", sigBinary, "."}
	}
	build := exec.Command("go", buildArgs...)
	build.Stdout = os.Stderr
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "failed to build sig: %v\n", err)
		os.RemoveAll(dir)
		os.Exit(1)
	}
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

// ---------------------------------------------------------------------------
// Plan schema
// ---------------------------------------------------------------------------

// seedEntry places one input before the case runs. The target is a path
// relative to the working directory, or "stdin" to feed the stream.
type seedEntry struct {
	Target   string  `json:"target"`
	From     string  `json:"from"`
	Text     *string `json:"text"`
	ReadOnly bool    `json:"read_only"`
}

// assertEntry is one assertion about one target. Exactly one verb is set.
type assertEntry struct {
	Target    string  `json:"target"`
	Exists    *bool   `json:"exists"`
	Match     string  `json:"match"`
	MatchText *string `json:"match_text"`
	Contains  *string `json:"contains"`
}

type conformanceCase struct {
	Name   string        `json:"name"`
	Note   string        `json:"note"`
	Argv   []string      `json:"argv"`
	Exit   int           `json:"exit"`
	Seed   []seedEntry   `json:"seed"`
	Assert []assertEntry `json:"assert"`
}

type caseFile struct {
	Group string            `json:"group"`
	Note  string            `json:"note"`
	Cases []conformanceCase `json:"cases"`
}

// verbs reports which assertion verbs an entry sets.
func (a assertEntry) verbs() []string {
	var set []string
	if a.Exists != nil {
		set = append(set, "exists")
	}
	if a.Match != "" {
		set = append(set, "match")
	}
	if a.MatchText != nil {
		set = append(set, "match_text")
	}
	if a.Contains != nil {
		set = append(set, "contains")
	}
	return set
}

// validateCase rejects a plan the runner could not check faithfully.
func validateCase(tc conformanceCase) error {
	for _, seed := range tc.Seed {
		if seed.Target == "" {
			return errors.New("seed entry has no target")
		}
		if seed.Target == targetStdout {
			return errors.New("seed target stdout is an output stream")
		}
		if (seed.From == "") == (seed.Text == nil) {
			return fmt.Errorf("seed %q needs exactly one of from or text", seed.Target)
		}
		if seed.ReadOnly && seed.Target == targetStdin {
			return errors.New("seed stdin cannot be read only")
		}
	}

	for _, entry := range tc.Assert {
		if entry.Target == "" {
			return errors.New("assert entry has no target")
		}
		if entry.Target == targetStdin {
			return errors.New("assert target stdin is an input stream")
		}
		if verbs := entry.verbs(); len(verbs) != 1 {
			return fmt.Errorf("assert on %q sets %d verbs (%v), expected exactly one",
				entry.Target, len(verbs), verbs)
		}
		if entry.Exists != nil && entry.Target == targetStdout {
			return errors.New("assert on stdout cannot use exists, a stream is not a file")
		}
		// Asserting an empty substring would always pass, so it is a plan bug
		// rather than a weak assertion.
		if entry.Contains != nil && *entry.Contains == "" {
			return fmt.Errorf("assert on %q contains an empty string, which always passes", entry.Target)
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Reference matching
// ---------------------------------------------------------------------------

// refPart is one piece of a parsed reference: a run of literal bytes, a
// {b64:N} token, or an {any} token.
type refPart struct {
	literal []byte
	b64Len  int
	anyRun  bool
}

func (p refPart) isLiteral() bool { return !p.anyRun && p.b64Len < 0 }

// scanToken reads a wildcard token from the front of ref.
func scanToken(ref []byte) (refPart, int, bool) {
	if rest, ok := bytes.CutPrefix(ref, []byte("{any}")); ok {
		return refPart{anyRun: true, b64Len: -1}, len(ref) - len(rest), true
	}
	rest, ok := bytes.CutPrefix(ref, []byte("{b64:"))
	if !ok {
		return refPart{}, 0, false
	}
	digits, _, ok := bytes.Cut(rest, []byte("}"))
	if !ok || len(digits) == 0 {
		return refPart{}, 0, false
	}
	// Digits only, so that Go and Python accept exactly the same tokens.
	// strconv.Atoi would otherwise take a sign that Python's isdigit rejects.
	for _, c := range digits {
		if c < '0' || c > '9' {
			return refPart{}, 0, false
		}
	}
	size, err := strconv.Atoi(string(digits))
	if err != nil {
		return refPart{}, 0, false
	}
	return refPart{b64Len: size}, len("{b64:") + len(digits) + len("}"), true
}

// parseReference splits a reference into literal runs and wildcard tokens. A
// brace that does not open a token is an ordinary byte.
func parseReference(ref []byte) ([]refPart, error) {
	var parts []refPart
	var literal []byte
	flush := func() {
		if len(literal) > 0 {
			parts = append(parts, refPart{literal: literal, b64Len: -1})
			literal = nil
		}
	}
	for len(ref) > 0 {
		index := bytes.IndexByte(ref, '{')
		if index < 0 {
			literal = append(literal, ref...)
			break
		}
		part, size, ok := scanToken(ref[index:])
		if !ok {
			literal = append(literal, ref[:index+1]...)
			ref = ref[index+1:]
			continue
		}
		literal = append(literal, ref[:index]...)
		flush()
		parts = append(parts, part)
		ref = ref[index+size:]
	}
	flush()

	for i := 1; i < len(parts); i++ {
		if !parts[i-1].isLiteral() && !parts[i].isLiteral() {
			return nil, errors.New("two wildcard tokens are adjacent, so neither has a boundary")
		}
	}
	return parts, nil
}

// normalize decompresses gzipped content. Go's compress/flate and zlib emit
// different streams for the same input, so a signed document is only ever
// compared in its plain form.
func normalize(data []byte) ([]byte, error) {
	if len(data) < 2 || data[0] != 0x1f || data[1] != 0x8b {
		return data, nil
	}
	reader, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("failed to decompress: %w", err)
	}
	defer reader.Close()
	var out bytes.Buffer
	if _, err := io.Copy(&out, reader); err != nil {
		return nil, fmt.Errorf("failed to decompress: %w", err)
	}
	return out.Bytes(), nil
}

// position renders a byte offset as a line and column for error messages.
func position(data []byte, offset int) string {
	if offset > len(data) {
		offset = len(data)
	}
	line := bytes.Count(data[:offset], []byte("\n")) + 1
	column := offset - (bytes.LastIndexByte(data[:offset], '\n') + 1) + 1
	return fmt.Sprintf("line %d column %d", line, column)
}

// excerpt renders a short, printable window of data around offset. A reference
// can run to 128 KB, so a mismatch must never dump both sides in full.
func excerpt(data []byte, offset int) string {
	const window = 60
	start := max(offset-window/2, 0)
	end := min(start+window, len(data))
	text := strconv.Quote(string(data[start:end]))
	if start > 0 {
		text = "..." + text
	}
	if end < len(data) {
		text += "..."
	}
	return text
}

// matchReference compares got against a reference holding literal runs and
// wildcard tokens. Both sides are decompressed first.
func matchReference(ref, got []byte) error {
	parts, err := parseReference(ref)
	if err != nil {
		return err
	}
	got, err = normalize(got)
	if err != nil {
		return err
	}

	pos := 0
	for i, part := range parts {
		switch {
		case part.isLiteral():
			if !bytes.HasPrefix(got[pos:], part.literal) {
				shared := 0
				for shared < len(part.literal) && pos+shared < len(got) && got[pos+shared] == part.literal[shared] {
					shared++
				}
				return fmt.Errorf("content differs at %s\n  expected: %s\n  got:      %s",
					position(got, pos+shared), excerpt(part.literal, shared), excerpt(got, pos+shared))
			}
			pos += len(part.literal)

		case part.b64Len >= 0:
			width := base64.RawStdEncoding.EncodedLen(part.b64Len)
			if pos+width > len(got) {
				return fmt.Errorf("expected a %d byte base64 value at %s, but only %d bytes remain",
					part.b64Len, position(got, pos), len(got)-pos)
			}
			chunk := got[pos : pos+width]
			decoded, err := base64.RawStdEncoding.DecodeString(string(chunk))
			if err != nil {
				return fmt.Errorf("expected a %d byte base64 value at %s, but it does not decode: %w",
					part.b64Len, position(got, pos), err)
			}
			if len(decoded) != part.b64Len {
				return fmt.Errorf("expected a %d byte base64 value at %s, got %d bytes",
					part.b64Len, position(got, pos), len(decoded))
			}
			pos += width

		default: // {any}
			if i == len(parts)-1 {
				if pos == len(got) {
					return fmt.Errorf("expected content for {any} at %s, got nothing", position(got, pos))
				}
				pos = len(got)
				continue
			}
			next := parts[i+1].literal
			offset := bytes.Index(got[pos:], next)
			if offset < 0 {
				return fmt.Errorf("no end found for {any} at %s: expected %s later in the content",
					position(got, pos), excerpt(next, 0))
			}
			if offset == 0 {
				return fmt.Errorf("expected content for {any} at %s, got nothing", position(got, pos))
			}
			pos += offset
		}
	}
	if pos != len(got) {
		return fmt.Errorf("content is longer than expected, %d trailing bytes from %s: %s",
			len(got)-pos, position(got, pos), excerpt(got, pos))
	}
	return nil
}

// ---------------------------------------------------------------------------
// Sandbox
// ---------------------------------------------------------------------------

// readFixture reads a seed source or a match reference. Both resolve against
// the committed fixtures rather than the group's copy, so a case that has
// already written over its input still compares against the original, and an
// expectation that genuinely is an existing fixture names it directly rather
// than being duplicated as a second copy.
func readFixture(name string) ([]byte, error) {
	return os.ReadFile(filepath.Join(fixtureDir, filepath.FromSlash(name)))
}

// copyTree copies src to dst so a group can be handed fixtures of its own.
func copyTree(dst, src string) error {
	return filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		if info.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(target, data, 0o644)
	})
}

// discard removes a temporary tree. Read only files, whether seeded that way
// or copied from a read only fixture, would otherwise block removal.
func discard(dir string) {
	filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() {
			os.Chmod(path, 0o644)
		}
		return nil
	})
	os.RemoveAll(dir)
}

// ---------------------------------------------------------------------------
// Running a case
// ---------------------------------------------------------------------------

// applyContent runs one content assertion against the bytes a target holds.
func applyContent(t *testing.T, entry assertEntry, got []byte) {
	t.Helper()
	what := entry.Target

	switch {
	case entry.Match != "":
		ref, err := readFixture(entry.Match)
		if err != nil {
			t.Fatalf("%s: failed to read reference %s: %v", what, entry.Match, err)
		}
		if ref, err = normalize(ref); err != nil {
			t.Fatalf("%s: reference %s: %v", what, entry.Match, err)
		}
		// A reference is compared as it sits on disk. Only the inline verbs
		// take placeholders, since only they are written in the plan.
		if err := matchReference(ref, got); err != nil {
			t.Errorf("%s: does not match %s\n%v", what, entry.Match, err)
		}

	case entry.MatchText != nil:
		if err := matchReference([]byte(*entry.MatchText), got); err != nil {
			t.Errorf("%s: does not match the expected text\n%v", what, err)
		}

	case entry.Contains != nil:
		plain, err := normalize(got)
		if err != nil {
			t.Fatalf("%s: %v", what, err)
		}
		want := *entry.Contains
		if !bytes.Contains(plain, []byte(want)) {
			t.Errorf("%s: expected to contain %q", what, want)
		}
	}
}

func runCase(t *testing.T, tc conformanceCase) {
	t.Helper()

	if err := validateCase(tc); err != nil {
		t.Fatalf("Case is not well formed: %v", err)
	}

	var stdinData []byte
	haveStdin := false
	for _, seed := range tc.Seed {
		var data []byte
		if seed.From != "" {
			fixture, err := readFixture(seed.From)
			if err != nil {
				t.Fatalf("Failed to read fixture %s: %v", seed.From, err)
			}
			data = fixture
		} else {
			data = []byte(*seed.Text)
		}
		if seed.Target == targetStdin {
			stdinData, haveStdin = data, true
			continue
		}
		target := filepath.FromSlash(seed.Target)
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			t.Fatalf("Failed to create seed directory: %v", err)
		}
		if err := os.WriteFile(target, data, 0o644); err != nil {
			t.Fatalf("Failed to seed %s: %v", seed.Target, err)
		}
		if seed.ReadOnly {
			if err := os.Chmod(target, 0o444); err != nil {
				t.Fatalf("Failed to make %s read only: %v", seed.Target, err)
			}
		}
	}

	cmd := exec.Command(sigBinary, tc.Argv...)
	if haveStdin {
		cmd.Stdin = bytes.NewReader(stdinData)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	exitCode := 0
	if err := cmd.Run(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			exitCode = exitErr.ExitCode()
		} else {
			t.Fatalf("Failed to run sig: %v", err)
		}
	}

	if exitCode != tc.Exit {
		t.Errorf("Expected exit code %d, got %d. Stderr: %s", tc.Exit, exitCode, stderr.String())
	}

	for _, entry := range tc.Assert {
		if entry.Exists != nil {
			_, err := os.Stat(filepath.FromSlash(entry.Target))
			switch {
			case *entry.Exists && err != nil:
				t.Errorf("%s: expected the file to exist: %v", entry.Target, err)
			case !*entry.Exists && err == nil:
				t.Errorf("%s: expected the file not to exist, but it does", entry.Target)
			case err != nil && !os.IsNotExist(err):
				t.Errorf("%s: %v", entry.Target, err)
			}
			continue
		}

		var got []byte
		switch entry.Target {
		case targetStdout:
			got = stdout.Bytes()
		default:
			data, err := os.ReadFile(filepath.FromSlash(entry.Target))
			if err != nil {
				t.Errorf("%s: expected content, but the file could not be read: %v", entry.Target, err)
				continue
			}
			got = data
		}
		applyContent(t, entry, got)
	}
}

func TestConformance(t *testing.T) {
	paths, err := filepath.Glob(filepath.Join("test", "cases", "*.json"))
	if err != nil {
		t.Fatalf("Failed to list case files: %v", err)
	}
	if len(paths) == 0 {
		t.Fatal("No case files found in test/cases")
	}
	sort.Strings(paths)

	total := 0
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("Failed to read %s: %v", path, err)
		}
		var file caseFile
		decoder := json.NewDecoder(bytes.NewReader(data))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&file); err != nil {
			t.Fatalf("Failed to parse %s: %v", path, err)
		}

		total += len(file.Cases)
		t.Run(file.Group, func(t *testing.T) {
			// Each group gets its own copy of the fixtures, shared by its
			// cases in order so a case can consume what an earlier one
			// produced, and thrown away afterwards so that nothing the group
			// does reaches the committed files.
			testDir, err := os.MkdirTemp("", "sig_conf")
			if err != nil {
				t.Fatalf("Failed to create sandbox: %v", err)
			}
			t.Cleanup(func() { discard(testDir) })
			if err := copyTree(testDir, fixtureDir); err != nil {
				t.Fatalf("Failed to copy fixtures: %v", err)
			}

			// The copy is the working directory, so a case names its files
			// exactly as the plan writes them. Chdir is process wide, which is
			// why no test here runs in parallel. t.Chdir restores the old
			// directory before the cleanup above removes this one.
			t.Chdir(testDir)

			for _, tc := range file.Cases {
				t.Run(tc.Name, func(t *testing.T) {
					runCase(t, tc)
				})
			}
		})
	}
	t.Logf("ran %d conformance cases from %d group files", total, len(paths))
}

// ---------------------------------------------------------------------------
// Matcher unit tests. The token syntax is implemented twice, once here and
// once in cli_test.py, so both copies are pinned directly.
// ---------------------------------------------------------------------------

func TestMatchReference(t *testing.T) {
	// 6 bytes encode to 8 base64 characters with no padding, 9 bytes to 12.
	six := base64.RawStdEncoding.EncodeToString([]byte("abcdef"))
	nine := base64.RawStdEncoding.EncodeToString([]byte("abcdefghi"))

	tests := []struct {
		name string
		ref  string
		got  string
		fail string // substring of the expected error, empty when it should match
	}{
		{name: "Exact", ref: "hello\n", got: "hello\n"},
		{name: "Empty", ref: "", got: ""},
		{name: "Trailing Bytes", ref: "hello", got: "hello there", fail: "longer than expected"},
		{name: "Truncated", ref: "hello there", got: "hello", fail: "differs at line 1 column 6"},
		{name: "Differs Late", ref: "a\nb\nc\n", got: "a\nb\nd\n", fail: "differs at line 3 column 1"},

		{name: "Token", ref: "key:{b64:6}\n", got: "key:" + six + "\n"},
		{name: "Token At End", ref: "key:{b64:6}", got: "key:" + six},
		{name: "Token Truncated", ref: "key:{b64:6}", got: "key:AAAA", fail: "only 4 bytes remain"},
		{name: "Token Bad Alphabet", ref: "key:{b64:6}\n", got: "key:****!!!!\n", fail: "does not decode"},
		{name: "Token Too Long For Content", ref: "key:{b64:9}\n", got: "key:" + six + "\n", fail: "only 9 bytes remain"},
		{name: "Token Is Not Greedy", ref: "key:{b64:6}\n", got: "key:" + nine + "\n", fail: "differs at line 1 column 13"},
		{name: "Token Then Mismatch", ref: "key:{b64:6}!\n", got: "key:" + six + "?\n", fail: "differs at line 1 column 13"},

		{name: "Any", ref: "etag:{any}\n", got: "etag:W/\"abc\"\n"},
		{name: "Any At End", ref: "{any}", got: "anything at all"},
		{name: "Any Empty At End", ref: "{any}", got: "", fail: "got nothing"},
		{name: "Any Empty Inline", ref: "a{any}b", got: "ab", fail: "got nothing"},
		{name: "Any No Boundary", ref: "a{any}b", got: "annn", fail: "no end found"},

		{name: "Brace Literal", ref: "a{b}c", got: "a{b}c"},
		{name: "Brace Unclosed", ref: "a{b64:c", got: "a{b64:c"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := matchReference([]byte(test.ref), []byte(test.got))
			switch {
			case test.fail == "" && err != nil:
				t.Errorf("Expected a match, got error: %v", err)
			case test.fail != "" && err == nil:
				t.Errorf("Expected an error containing %q, got a match", test.fail)
			case test.fail != "" && !strings.Contains(err.Error(), test.fail):
				t.Errorf("Expected an error containing %q, got: %v", test.fail, err)
			}
		})
	}
}

func TestMatchReferenceGunzips(t *testing.T) {
	var buffer bytes.Buffer
	writer := gzip.NewWriter(&buffer)
	if _, err := writer.Write([]byte("plain content\n")); err != nil {
		t.Fatalf("Failed to compress: %v", err)
	}
	writer.Close()

	if err := matchReference([]byte("plain content\n"), buffer.Bytes()); err != nil {
		t.Errorf("Expected the gzipped content to match its plain reference: %v", err)
	}
}

func TestParseReferenceRejectsAdjacentTokens(t *testing.T) {
	if _, err := parseReference([]byte("{any}{b64:6}")); err == nil {
		t.Error("Expected adjacent wildcard tokens to be rejected")
	}
}

func TestValidateCase(t *testing.T) {
	text := ""
	word := "x"
	yes := true
	tests := []struct {
		name string
		tc   conformanceCase
		fail string
	}{
		{
			name: "No Verb",
			tc: conformanceCase{Assert: []assertEntry{
				{Target: "out.txt"},
			}},
			fail: "sets 0 verbs",
		},
		{
			name: "Two Verbs",
			tc: conformanceCase{Assert: []assertEntry{
				{Target: "stdout", Match: "expected.txt", Contains: &word},
			}},
			fail: "sets 2 verbs",
		},
		{
			name: "Empty Contains",
			tc: conformanceCase{Assert: []assertEntry{
				{Target: "stdout", Contains: &text},
			}},
			fail: "always passes",
		},
		{
			name: "Exists On Stream",
			tc: conformanceCase{Assert: []assertEntry{
				{Target: "stdout", Exists: &yes},
			}},
			fail: "a stream is not a file",
		},
		{
			name: "Assert On Stdin",
			tc: conformanceCase{Assert: []assertEntry{
				{Target: "stdin", MatchText: &text},
			}},
			fail: "stdin is an input stream",
		},
		{
			name: "Seed Both Sources",
			tc: conformanceCase{Seed: []seedEntry{
				{Target: "in.txt", From: "test.txt", Text: &text},
			}},
			fail: "exactly one of from or text",
		},
		{
			name: "Seed Onto Stdout",
			tc: conformanceCase{Seed: []seedEntry{
				{Target: "stdout", From: "test.txt"},
			}},
			fail: "is an output stream",
		},
		{
			name: "Valid",
			tc: conformanceCase{
				Seed:   []seedEntry{{Target: "stdin", From: "test.txt"}},
				Assert: []assertEntry{{Target: "stdout", Match: "expected.txt"}},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateCase(test.tc)
			switch {
			case test.fail == "" && err != nil:
				t.Errorf("Expected the case to validate, got error: %v", err)
			case test.fail != "" && err == nil:
				t.Errorf("Expected an error containing %q, got none", test.fail)
			case test.fail != "" && !strings.Contains(err.Error(), test.fail):
				t.Errorf("Expected an error containing %q, got: %v", test.fail, err)
			}
		})
	}
}
