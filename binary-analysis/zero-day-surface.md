# Zero-Day Candidate Discovery

**347 binaries, 235,333 functions, 1126 risky-import functions**

## Top Zero-Day Candidates (High Risky-Import Density, No/Low Known CVEs)

| Binary | Functions | Risky Imports | Priority |
|--------|-----------|---------------|----------|
| imhex | 1640 | 74 | P0 |
| qemu-img | 7901 | 68 | P0 |
| gpg | 2558 | 30 | P0 |
| pppd | 1194 | 28 | P0 |
| ssh | 2101 | 28 | P0 |
| rsyslogd | 1859 | 24 | P0 |
| apache2 | 2605 | 22 | P0 |
| ssh-keygen | 1463 | 22 | P0 |
| i686-w64-mingw32-gcov-win32 | 3141 | 21 | P0 |
| bash | 2881 | 20 | P0 |
| gcc | 2523 | 20 | P0 |
| hydra | 1027 | 20 | P0 |
| make | 660 | 20 | P0 |
| nc | 160 | 20 | P0 |
| passwd | 612 | 20 | P0 |
| sftp | 763 | 20 | P0 |
| sudo | 841 | 20 | P0 |
| x86_64-w64-mingw32-gcov-dump-posix | 2870 | 19 | P0 |
| sshd | 1448 | 18 | P0 |
| sz | 257 | 18 | P0 |
| unzip | 285 | 18 | P0 |
| x86_64-w64-mingw32ucrt-readelf | 1166 | 18 | P0 |
| afl-network-server | 258 | 16 | P0 |
| atril-previewer | 468 | 16 | P0 |
| grub-macbless | 2030 | 16 | P0 |
| pth-curl | 2468 | 16 | P0 |
| rsync | 1142 | 16 | P0 |
| scp | 716 | 16 | P0 |
| wget | 1138 | 16 | P0 |
| fsck.fat | 228 | 14 | P1 |

**Total zero-day candidate surfaces: 1126 across 347 binaries**

Each binary has full Ghidra output: functions.jsonl (entry points), symbols.jsonl (ASLR vectors), strings.txt (credential paths), risky-functions.jsonl (buffer overflow targets).
