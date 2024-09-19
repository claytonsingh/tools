# exchange

A simple C program to atomically exchange two files or folders using the `renameat2(2)` system call.

## Description

This program provides a command-line interface to the `renameat2` system call with the `RENAME_EXCHANGE` flag, allowing users to atomically swap the names of two files or directories.

## Notes

- This program requires a Linux kernel that supports the `renameat2` system call (Linux 3.15 and later).
- The program uses direct system calls, which may not be portable across all Linux distributions or kernel versions.

## Building

To compile the program, use:
```bash
gcc exchange.c -s -Os -o exchange
cp exchange /usr/local/bin/exchange
```

## Usage
To exchange two files or directories, run:
```
./exchange file1.txt file2.txt
./exchange dir1 dir2
```

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
