# Coding Project 1 - Part 1: SCANGRAB grab client

## Contents

cgrab.c is the C grab client (TCP). The Makefile builds it into the cgrab executable in this directory. batchgrab is a shell script that fetches every file listed in a CLRTOSCAN-style list. The .gitignore file keeps the compiled binary, object files, and the scans directory out of the repository.

## Build

Run make in this directory. Run make clean to remove the executable.

## Usage

To grab a single file, run: ./cgrab FILE HOST PORT AUTH

To grab a whole list of files, run: ./batchgrab LISTFILE

Run both from this directory. Downloads go to the scans subdirectory, which is created automatically. Existing files are overwritten without prompting.

batchgrab expects one entry per line in the form FILE HOST PORT AUTH, for example: F001.dat 127.0.0.6 54100 SweetAuth. Blank lines, lines starting with #, and the CLRTOSCAN, START-LIST, and END-LIST lines are skipped. A failed file does not stop the batch. A summary is printed at the end, and the exit status is 0 only if every entry succeeded.

## How cgrab works

First, cgrab opens a TCP connection, sends an INFO command, and parses the INFO-RESP reply to get the file size and MD5 checksum. Second, it opens a new connection, sends a GRAB command, parses the GRAB-RESP header, and reads exactly SIZE raw bytes of binary content. Third, it streams the data to a temporary file in the scans directory while computing the MD5 checksum with a built-in implementation (no OpenSSL needed). The temporary file is renamed to its final name only if both the size and the MD5 match. On any failure, the partial file is removed and cgrab exits with status 1.

It handles zero-byte files, large files (read in 64 KB chunks with progress output), bad authorization or unknown files (the server's error text is printed), dropped connections, and a 30 second receive timeout.

## Notes and caveats

Commands are sent exactly as shown in the project description, with no trailing newline. If a server needs newline-terminated commands, set the environment variable CGRAB_NEWLINE=1 before running cgrab.

Only the base name of FILE is used for the local path, so cgrab cannot write outside the scans directory.

If the executable bit is lost after cloning, run chmod +x batchgrab.

## Authors

Medihin (Natu) Daniel
