```bash
sudo pacman -Syu git wget make

git clone https://github.com/Prslc/kpm_demo.git

wget arm-gnu-toolchain-12.2.rel1-x86_64-aarch64-none-elf.tar.xz https://armkeil.blob.core.windows.net/developer/Files/downloads/gnu/12.2.rel1/binrel/arm-gnu-toolchain-12.2.rel1-x86_64-aarch64-none-elf.tar.xz

tar -xvf arm-gnu-toolchain-12.2.rel1-x86_64-aarch64-none-elf.tar.xz

export TARGET_COMPILE=<arm-gnu-toolchain_dir>/bin/aarch64-none-elf-

cd kpm_demo

git submodule update --init --recursive

cd <module_name>

make
```
