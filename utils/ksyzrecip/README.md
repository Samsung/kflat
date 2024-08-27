# ksyzrecip - syzkaller descriptions <-> KFLAT recipes translator

`ksyzrecip` automatically coverts syzkaller descriptions to KFLAT recipe by plugging into Syzkaller recipe compiler.  

`ksyzrecip` generates a flattening functions for each possible (described in passed descriptions) type passed to a viable syscall, as well as trigger functions for each supported syscall.

This tool utilizes [FOKA](https://github.com/Samsung/seal), a kernel syscall2fspath mapper, for generating trigger functions.
For more informations, check the FOKA repo

## Usage
```sh
$ ksyzrecip -help
Usage of ./ksyzrecip:
  -arch string
        targeted arch of syzkaller descriptions (sizes or constants might differ) from sys/targets package (default "arm64")
  -foka string
        path to FOKA output (default "foka_v2.json")
  -output string
        path to outputted file (default "_gen.c")

Most importantly ksyzrecip takes at least 1 positional argument which is a path to folder with syzkaller descriptions.
Normally that would be in syzkaller/sys/$TARGETOS
$
$ ./ksyzrecip /home/me/syzkaller/sys/models/linux/
```
