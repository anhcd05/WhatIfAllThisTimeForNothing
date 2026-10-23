#!/bin/bash
cd /home/kali/algo_lab
bash ida_batch.sh algos_gcc_O0 30 gm xt
bash ida_batch.sh algos_gcc_O2 30
bash ida_batch.sh algos_mingw_O0.exe 75
bash ida_batch.sh algos_mingw_O2.exe 75
echo ALLDONE > /home/kali/algo_lab/pc/_alldone