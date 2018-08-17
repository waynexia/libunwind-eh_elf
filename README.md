# libunwind, `eh_elf` flavour

This repository is a fork of `libunwind`. The original `README` file is
preserved as `README.original`.

## Compiling

```bash
./autogen.sh
./configure --enable-maintainer-mode --enable-debug
make -j
```

It is also advised to install this libunwind version to some place of your
system, for instance `$HOME/local/libunwind-eh_elf`. For this purpose, pass an
additional `--prefix=~/local/libunwind-eh_elf` to `./configure`, and after
building the library, run `make install` (possibly with root permissions if you
installed it to `/usr/local/...`).
