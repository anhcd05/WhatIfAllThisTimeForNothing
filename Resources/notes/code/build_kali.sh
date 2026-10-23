#!/bin/bash
# Chay tren Kali: sinh tables.h, build gcc (ELF) va mingw (PE) o O0 va O2, chay ELF va so sanh
cd ~/algo_lab || exit 1
exec > build_kali.log 2>&1
set -x
python3 gen_tables.py tables.h
mkdir -p bin
gcc -O0 -o bin/algos_gcc_O0 algos.c
gcc -O2 -o bin/algos_gcc_O2 algos.c
x86_64-w64-mingw32-gcc -O0 -static -o bin/algos_mingw_O0.exe algos.c
x86_64-w64-mingw32-gcc -O2 -static -o bin/algos_mingw_O2.exe algos.c
ls -la bin
for b in algos_gcc_O0 algos_gcc_O2; do ./bin/$b > bin/$b.out; echo "$b rc=$?"; done
cmp bin/algos_gcc_O0.out bin/algos_gcc_O2.out && echo "O0==O2 output identical"
set +x
echo "---- output O0"; cat bin/algos_gcc_O0.out
