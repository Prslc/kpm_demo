```bash
sudo pacman -Syu make

git --recurse-submodules clone https://github.com/Prslc/kpm_demo.git

wget https://developer.arm.com/-/media/Files/downloads/gnu/14.2.rel1/binrel/arm-gnu-toolchain-14.2.rel1-x86_64-aarch64-none-elf.tar.xz

tar -xvf arm-gnu-toolchain-14.2.rel1-x86_64-aarch64-none-elf.tar.xz

cd kpm_demo/<module_name>

export TARGET_COMPILE=<arm-gnu-toolchain_dir>/bin/aarch64-none-elf-

make
```