# Conformance test plan

These files are the shared CLI test plan for both implementations. The Go suite
runs them from `cli_test.go` and the Python suite from `cli_test.py`. Neither
runner knows about the other: because every expectation is declared here, both
suites passing is what proves the two implementations agree.

## The contract

For a given input (argv, stdin, key files, input files) both implementations
must produce the same exit code, the same stdout, and the same files in the
working directory.

Stderr is not part of the contract. The two implementations word their
diagnostics differently and that is allowed. Usage and help text on stdout is
not compared either, since go-flags and argparse cannot be made to agree.

Exit codes are 0 success, 1 error, 2 argument error, 3 content not modified.

Gzip is never compared byte for byte. Go's `compress/flate` and zlib produce
different streams at the same level, so the runner decompresses anything
starting with the gzip magic before it compares. An expectation therefore names
the plain form even when the command wrote a `.gz`.

## Layout

One file per group. A runner takes a group by copying the fixture directory
into a temporary directory, changing into it, running the group's cases in file
order, and deleting the copy afterwards. So a case may consume what an earlier
case in the same group produced, and groups are independent of each other.

Because the copy is the working directory, every path in a case is a plain
relative name, and a case that writes over its input cannot disturb the
committed files. Groups run one at a time, since the working directory is
process wide, but the two suites can still run at the same time as each other.

```json
{
  "group": "shortinput",
  "note": "why this group exists",
  "cases": [ ... ]
}
```

## Case fields

- `name`: subtest name, unique within the group.
- `note`: optional prose explaining what the case pins and why. JSON has no
  comment syntax, so this is where the reasoning goes.
- `argv`: arguments passed to the implementation. Not a shell string.
- `exit`: expected exit code, defaulting to 0.
- `seed`: inputs placed before the case runs, see below.
- `assert`: everything expected of the run, see below.

Nothing in a case is substituted before it is used. A path is written as the
relative name it already is, because the case runs in the directory that holds
it, and the fetch URLs are written out in full. That also keeps paths out of
expected output: a command that echoes back a file it was given prints the same
relative name on both runners, on every machine.

The only things not taken literally are the two wildcard tokens below, and they
are read where a reference is compared rather than substituted into it.

## Targets

Both lists are keyed by a target. `stdout` and `stdin` name streams; anything
else is a path relative to the working directory, always with forward slashes.
The stream names are reserved and cannot be used as paths.

There is no `stderr` target. The two implementations word their diagnostics
differently, so stderr is outside the contract and a case cannot assert on it.

## Seed entries

```json
"seed": [
  {"target": "doc.txt", "from": "test.txt", "read_only": true},
  {"target": "stdin",   "from": "test.txt.sig.gz"},
  {"target": "stdin",   "text": "hello\n"}
]
```

Exactly one of `from`, naming a fixture, or `text`, holding it inline.

A seed lands in the working directory alongside the fixtures, so a file target
picks a name no fixture already has. `from` still reads the committed original,
so a seed can be a modified copy of a fixture but not a replacement for one.

## Assert entries

Each entry names a target and sets exactly one verb.

- `exists`: `true` or `false`, whether the path is there after the run. Only
  for file targets, since a stream is not a file. `false` is how a case states
  that a failed run left nothing behind.
- `match`: the content equals the named reference. The name resolves against
  the fixture directory, so `test.txt` is the document fixture itself and
  `inspect_single.txt` is an expected output.
- `match_text`: the content equals this inline reference.
- `contains`: the content holds this string, compared literally. This is the
  loose verb, for output like help text that the two implementations are
  allowed to lay out differently. To require several strings, write several
  entries; the list already provides that, so the verb does not repeat it.
  It is deliberately not a regex: the two engines disagree on repeat limits
  and lookarounds, so a pattern could pass on one runner and fail to compile
  on the other, and fingerprints are base64 so `+` and `/` would need
  escaping.

A target may carry several entries, so stdout can be matched and searched at
once.

### Asserting that nothing was written

The runner does not track what changed on disk; every assertion is stated. A
case whose run should fail before it writes says so directly:

```json
{"target": "verify-wrong.txt", "exists": false}
```

That is what catches the zero-byte file a failed verify would leave behind if
it opened its destination before validating, and the partial write from an
aborted sign. Cases that fail on their arguments have no destination to name,
so they assert only their exit code.

`exists: true` is rarely needed, because asserting content already requires the
file to be there and to be readable.

## References and wildcards

A reference is compared exactly, in order, byte for byte. That makes an expected
inspect output pin its sort order, its padding, its header set and its values
all at once, with no assertion code behind it.

Two tokens cover the only content the suite cannot predict:

- `{b64:N}`: an unpadded base64 run that decodes to exactly N bytes. Used for
  ML-DSA signatures, which are randomized, where it pins the parameter set by
  signature size. Not a regex: the counts run past Go's repeat limit, and a
  character count is not what the case means.
- `{any}`: a non-empty run up to whatever follows it. Used for the fetch ETag,
  which the server chooses.

Two tokens cannot be adjacent, since neither would have a boundary. A brace
that does not open a token is an ordinary byte.

## Expected outputs

Inputs and expected outputs share `test`, because which one a file is depends
on how the plan uses it rather than on where it sits. Both runners only read
them, so an expected output is a committed artifact like any other fixture.

Neither runner will rewrite one for you. When a deliberate change to the tool
makes an expected output stale, run the case's command by hand and save the
result over it, then run both suites to confirm the two implementations agree
on the new value. Nothing regenerates them in bulk, which is the point: every
change to an expected output is a reviewed edit.

An expected output whose ML-DSA signature is generated at run time carries a
`{b64:N}` token in place of the value. The ML-DSA signatures that come from a
committed fixture are fixed and stay literal.
