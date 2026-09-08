"""Conformance harness for the Python implementation.

The test plan lives in test/cases/*.json and is shared with the Go
implementation, which runs the same plan from cli_test.go. See
test/cases/README.md for the schema.

The contract being checked is exit code, stdout and the files left in the
working directory. Stderr is deliberately not part of it, because the two
implementations word their diagnostics differently, so it is not a target a
case can assert on at all. It is captured only to report a wrong exit code.

Every content assertion is an exact match against a reference, either a file
under test or inline text. Two wildcard tokens cover the only nondeterminism in
the suite: {b64:N} for a randomized signature and {any} for a server chosen
value. Both runners only ever read the references, which is what makes
agreement between them meaningful.

Run with pytest, or directly with python for a plain report.
"""

import base64
import contextlib
import glob
import gzip
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
TEST_DIR = os.path.join(HERE, "test")
CASES_DIR = os.path.join(TEST_DIR, "cases")
SIG_PY = os.path.join(HERE, "sig.py")

# Stream targets. Anything else names a path relative to the working directory.
TARGET_STDOUT = "stdout"
TARGET_STDIN = "stdin"
STREAMS = (TARGET_STDOUT, TARGET_STDIN)

# Go rejects unknown fields when it decodes the plan. Python has no equivalent,
# so the key sets are spelled out here to catch the same typos.
GROUP_KEYS = frozenset(["group", "note", "cases"])
CASE_KEYS = frozenset(["name", "note", "argv", "exit", "seed", "assert"])
SEED_KEYS = frozenset(["target", "from", "text", "read_only"])
ASSERT_KEYS = frozenset(["target", "exists", "match", "match_text", "contains"])
ASSERT_VERBS = ("exists", "match", "match_text", "contains")


class CaseFailure(Exception):
    """One or more assertions failed for a case."""


class PlanError(Exception):
    """The plan itself is malformed, which fails before anything runs."""


# ---------------------------------------------------------------------------
# Loading and validation
# ---------------------------------------------------------------------------

def check_keys(what, mapping, allowed):
    for key in mapping:
        if key not in allowed:
            raise PlanError("{0}: unknown field {1!r}".format(what, key))


def validate_case(what, case):
    """Reject a case the runner could not check faithfully."""
    check_keys(what, case, CASE_KEYS)

    for seed in case.get("seed") or []:
        check_keys(what, seed, SEED_KEYS)
        target = seed.get("target")
        if not target:
            raise PlanError(what + ": seed entry has no target")
        if target == TARGET_STDOUT:
            raise PlanError(what + ": seed target stdout is an output stream")
        if ("from" in seed) == ("text" in seed):
            raise PlanError("{0}: seed {1!r} needs exactly one of from or text".format(what, target))
        if seed.get("read_only") and target == TARGET_STDIN:
            raise PlanError(what + ": seed stdin cannot be read only")

    for entry in case.get("assert") or []:
        check_keys(what, entry, ASSERT_KEYS)
        target = entry.get("target")
        if not target:
            raise PlanError(what + ": assert entry has no target")
        if target == TARGET_STDIN:
            raise PlanError(what + ": assert target stdin is an input stream")

        verbs = [verb for verb in ASSERT_VERBS if verb in entry]
        if len(verbs) != 1:
            raise PlanError("{0}: assert on {1!r} sets {2} verbs ({3}), expected exactly one".format(
                what, target, len(verbs), verbs))

        if "exists" in entry and target in STREAMS:
            raise PlanError("{0}: assert on {1!r} cannot use exists, a stream is not a file".format(
                what, target))

        # Asserting an empty substring would always pass, so it is a plan bug
        # rather than a weak assertion
        if entry.get("contains") == "":
            raise PlanError("{0}: assert on {1!r} contains an empty string, which always passes".format(
                what, target))


def load_groups():
    groups = []
    for path in sorted(glob.glob(os.path.join(CASES_DIR, "*.json"))):
        handle = open(path, "r", encoding="utf-8")
        try:
            group = json.load(handle)
        finally:
            handle.close()
        check_keys(os.path.basename(path), group, GROUP_KEYS)
        for case in group["cases"]:
            validate_case(group["group"] + "/" + case["name"], case)
        groups.append((path, group))
    if not groups:
        raise PlanError("No case files found in " + CASES_DIR)
    return groups


def read_fixture(name):
    """Read a seed source or a match reference.

    Both resolve against the committed fixtures rather than the group's copy,
    so a case that has already written over its input still compares against
    the original, and an expectation that genuinely is an existing fixture
    names it directly rather than being duplicated as a second copy.
    """
    handle = open(os.path.join(TEST_DIR, name.replace("/", os.sep)), "rb")
    try:
        return handle.read()
    finally:
        handle.close()


# ---------------------------------------------------------------------------
# Reference matching
# ---------------------------------------------------------------------------

def normalize(data):
    """Decompress gzipped content.

    Go's compress/flate and zlib emit different streams for the same input, so
    a signed document is only ever compared in its plain form.
    """
    if data[:2] != b"\x1f\x8b":
        return data
    return gzip.decompress(data)


def scan_token(ref):
    """Read a wildcard token from the front of ref."""
    if ref.startswith(b"{any}"):
        return ("any", 0), len(b"{any}")
    if not ref.startswith(b"{b64:"):
        return None, 0
    end = ref.find(b"}", len(b"{b64:"))
    if end < 0:
        return None, 0
    digits = ref[len(b"{b64:"):end]
    if not digits.isdigit():
        return None, 0
    return ("b64", int(digits)), end + 1


def parse_reference(ref):
    """Split a reference into literal runs and wildcard tokens.

    A brace that does not open a token is an ordinary byte.
    """
    parts = []
    literal = b""
    while ref:
        index = ref.find(b"{")
        if index < 0:
            literal += ref
            break
        token, size = scan_token(ref[index:])
        if token is None:
            literal += ref[:index + 1]
            ref = ref[index + 1:]
            continue
        literal += ref[:index]
        if literal:
            parts.append(("literal", literal))
            literal = b""
        parts.append(token)
        ref = ref[index + size:]
    if literal:
        parts.append(("literal", literal))

    for i in range(1, len(parts)):
        if parts[i - 1][0] != "literal" and parts[i][0] != "literal":
            raise PlanError("two wildcard tokens are adjacent, so neither has a boundary")
    return parts


def decode_b64(chunk, size):
    """Decode an unpadded base64 run, returning None when it is not valid."""
    padded = chunk + b"=" * (-len(chunk) % 4)
    try:
        decoded = base64.b64decode(padded, validate=True)
    except Exception:
        return None
    if len(decoded) != size:
        return None
    return decoded


def position(data, offset):
    """Render a byte offset as a line and column for error messages."""
    offset = min(offset, len(data))
    line = data.count(b"\n", 0, offset) + 1
    column = offset - (data.rfind(b"\n", 0, offset) + 1) + 1
    return "line {0} column {1}".format(line, column)


def excerpt(data, offset):
    """Render a short, printable window of data around offset.

    A reference can run to 128 KB, so a mismatch must never dump both sides in
    full.
    """
    window = 60
    start = max(offset - window // 2, 0)
    end = min(start + window, len(data))
    text = repr(data[start:end].decode("utf-8", "replace"))
    if start > 0:
        text = "..." + text
    if end < len(data):
        text += "..."
    return text


def match_reference(ref, got):
    """Compare got against a reference holding literals and wildcard tokens.

    Returns None on a match, or a description of the first difference.
    """
    parts = parse_reference(ref)
    got = normalize(got)

    pos = 0
    for i, (kind, value) in enumerate(parts):
        if kind == "literal":
            if not got[pos:].startswith(value):
                shared = 0
                while (shared < len(value) and pos + shared < len(got)
                       and got[pos + shared] == value[shared]):
                    shared += 1
                return "content differs at {0}\n  expected: {1}\n  got:      {2}".format(
                    position(got, pos + shared), excerpt(value, shared), excerpt(got, pos + shared))
            pos += len(value)

        elif kind == "b64":
            # Length of value bytes in unpadded standard base64
            width = (value * 8 + 5) // 6
            if pos + width > len(got):
                return "expected a {0} byte base64 value at {1}, but only {2} bytes remain".format(
                    value, position(got, pos), len(got) - pos)
            if decode_b64(got[pos:pos + width], value) is None:
                return "expected a {0} byte base64 value at {1}, but it does not decode".format(
                    value, position(got, pos))
            pos += width

        else:  # any
            if i == len(parts) - 1:
                if pos == len(got):
                    return "expected content for {{any}} at {0}, got nothing".format(position(got, pos))
                pos = len(got)
                continue
            following = parts[i + 1][1]
            offset = got.find(following, pos)
            if offset < 0:
                return "no end found for {{any}} at {0}: expected {1} later in the content".format(
                    position(got, pos), excerpt(following, 0))
            if offset == pos:
                return "expected content for {{any}} at {0}, got nothing".format(position(got, pos))
            pos = offset

    if pos != len(got):
        return "content is longer than expected, {0} trailing bytes from {1}: {2}".format(
            len(got) - pos, position(got, pos), excerpt(got, pos))
    return None


# ---------------------------------------------------------------------------
# Sandbox
# ---------------------------------------------------------------------------

def apply_content(entry, got, errors):
    """Run one content assertion against the bytes a target holds."""
    what = entry["target"]

    if "match" in entry:
        # A reference is compared as it sits on disk. Only the inline verbs
        # take placeholders, since only they are written in the plan.
        problem = match_reference(normalize(read_fixture(entry["match"])), got)
        if problem is not None:
            errors.append("{0}: does not match {1}\n{2}".format(what, entry["match"], problem))

    elif "match_text" in entry:
        problem = match_reference(entry["match_text"].encode("utf-8"), got)
        if problem is not None:
            errors.append("{0}: does not match the expected text\n{1}".format(what, problem))

    elif "contains" in entry:
        want = entry["contains"].encode("utf-8")
        if want not in normalize(got):
            errors.append("{0}: expected to contain {1!r}".format(what, want))


def run_case(case):
    errors = []

    stdin_data = None
    for seed in case.get("seed") or []:
        if "from" in seed:
            data = read_fixture(seed["from"])
        else:
            data = seed["text"].encode("utf-8")
        if seed["target"] == TARGET_STDIN:
            stdin_data = data
            continue
        target = seed["target"].replace("/", os.sep)
        parent = os.path.dirname(target)
        if parent and not os.path.isdir(parent):
            os.makedirs(parent)
        handle = open(target, "wb")
        try:
            handle.write(data)
        finally:
            handle.close()
        if seed.get("read_only"):
            os.chmod(target, stat.S_IREAD)

    proc = subprocess.run(
        [sys.executable, SIG_PY] + case["argv"],
        input=stdin_data,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    want_exit = case.get("exit", 0)
    if proc.returncode != want_exit:
        errors.append("Expected exit code {0}, got {1}. Stderr: {2}".format(
            want_exit, proc.returncode, proc.stderr.decode("utf-8", "replace")))

    for entry in case.get("assert") or []:
        target = entry["target"]

        if "exists" in entry:
            present = os.path.exists(target.replace("/", os.sep))
            if entry["exists"] and not present:
                errors.append("{0}: expected the file to exist".format(target))
            elif not entry["exists"] and present:
                errors.append("{0}: expected the file not to exist, but it does".format(target))
            continue

        if target == TARGET_STDOUT:
            got = proc.stdout
        else:
            try:
                handle = open(target.replace("/", os.sep), "rb")
            except IOError as problem:
                errors.append("{0}: expected content, but the file could not be read: {1}".format(
                    target, problem))
                continue
            try:
                got = handle.read()
            finally:
                handle.close()
        apply_content(entry, got, errors)

    if errors:
        raise CaseFailure("\n".join(errors))


@contextlib.contextmanager
def sandbox():
    """Copy the fixtures into a temp directory and run the group inside it.

    The copy is the working directory, so a case names its files exactly as the
    plan writes them, and a case that writes over its input cannot disturb the
    committed files. Chdir is process wide, which is why groups run one at a
    time. The old directory is restored before the copy is removed, since a
    directory that is in use cannot be deleted on Windows.
    """
    root = tempfile.mkdtemp(prefix="sig_conf_py_")
    test_dir = os.path.join(root, "test")
    shutil.copytree(TEST_DIR, test_dir)
    previous = os.getcwd()
    os.chdir(test_dir)
    try:
        yield
    finally:
        os.chdir(previous)
        # Seeded read only files would otherwise block removal
        for base, _, names in os.walk(root):
            for name in names:
                try:
                    os.chmod(os.path.join(base, name), stat.S_IWRITE | stat.S_IREAD)
                except OSError:
                    pass
        shutil.rmtree(root, ignore_errors=True)


# ---------------------------------------------------------------------------
# pytest entry point. One test per group, so the cases in a group keep their
# order and their shared sandbox.
# ---------------------------------------------------------------------------

try:
    import pytest
except ImportError:
    pytest = None

if pytest is not None:
    _GROUPS = load_groups()

    @pytest.mark.parametrize(
        "path,group",
        _GROUPS,
        ids=[g["group"] for _, g in _GROUPS],
    )
    def test_conformance_group(path, group):
        with sandbox():
            for case in group["cases"]:
                try:
                    run_case(case)
                except CaseFailure as failure:
                    pytest.fail("{0}/{1}:\n{2}".format(group["group"], case["name"], failure))

    # The token syntax is implemented twice, once here and once in cli_test.go,
    # so both copies are pinned directly.
    SIX = base64.b64encode(b"abcdef").decode("ascii").rstrip("=")
    NINE = base64.b64encode(b"abcdefghi").decode("ascii").rstrip("=")

    @pytest.mark.parametrize("ref,got,fail", [
        ("hello\n", "hello\n", None),
        ("", "", None),
        ("hello", "hello there", "longer than expected"),
        ("hello there", "hello", "differs at line 1 column 6"),
        ("a\nb\nc\n", "a\nb\nd\n", "differs at line 3 column 1"),

        ("key:{b64:6}\n", "key:" + SIX + "\n", None),
        ("key:{b64:6}", "key:" + SIX, None),
        ("key:{b64:6}", "key:AAAA", "only 4 bytes remain"),
        ("key:{b64:6}\n", "key:****!!!!\n", "does not decode"),
        ("key:{b64:9}\n", "key:" + SIX + "\n", "only 9 bytes remain"),
        ("key:{b64:6}\n", "key:" + NINE + "\n", "differs at line 1 column 13"),
        ("key:{b64:6}!\n", "key:" + SIX + "?\n", "differs at line 1 column 13"),

        ("etag:{any}\n", "etag:W/\"abc\"\n", None),
        ("{any}", "anything at all", None),
        ("{any}", "", "got nothing"),
        ("a{any}b", "ab", "got nothing"),
        ("a{any}b", "annn", "no end found"),

        ("a{b}c", "a{b}c", None),
        ("a{b64:c", "a{b64:c", None),
    ])
    def test_match_reference(ref, got, fail):
        problem = match_reference(ref.encode("utf-8"), got.encode("utf-8"))
        if fail is None:
            assert problem is None, "Expected a match, got: " + str(problem)
        else:
            assert problem is not None, "Expected an error containing " + repr(fail)
            assert fail in problem, "Expected {0!r} in {1!r}".format(fail, problem)

    def test_match_reference_gunzips():
        assert match_reference(b"plain content\n", gzip.compress(b"plain content\n")) is None

    def test_parse_reference_rejects_adjacent_tokens():
        with pytest.raises(PlanError):
            parse_reference(b"{any}{b64:6}")


def main():
    groups = load_groups()
    total = 0
    failed = 0
    for _, group in groups:
        with sandbox():
            for case in group["cases"]:
                total += 1
                try:
                    run_case(case)
                except CaseFailure as failure:
                    failed += 1
                    print("FAIL " + group["group"] + "/" + case["name"])
                    for line in str(failure).split("\n"):
                        print("       " + line)
    print("")
    print("ran {0} cases from {1} group files, {2} failed".format(total, len(groups), failed))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
