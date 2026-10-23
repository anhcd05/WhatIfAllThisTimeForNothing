@echo off
rem Chay tren FlareVM: build MSVC Od va O2 (co PDB), chay va luu output
cd /d C:\Users\Public\algo_lab
call "C:\Program Files (x86)\Microsoft Visual Studio\2017\BuildTools\VC\Auxiliary\Build\vcvars64.bat" > build_msvc.log 2>&1
if not exist bin mkdir bin
cl /nologo /Od /Zi /MT /Fo:bin\algos_msvc_Od.obj /Fd:bin\algos_msvc_Od.pdb /Fe:bin\algos_msvc_Od.exe algos.c /link /DEBUG /INCREMENTAL:NO >> build_msvc.log 2>&1
cl /nologo /O2 /Zi /MT /Fo:bin\algos_msvc_O2.obj /Fd:bin\algos_msvc_O2.pdb /Fe:bin\algos_msvc_O2.exe algos.c /link /DEBUG /INCREMENTAL:NO >> build_msvc.log 2>&1
for %%B in (algos_msvc_Od algos_msvc_O2) do (
  bin\%%B.exe > bin\%%B.out 2>&1
  echo %%B rc=%ERRORLEVEL% >> build_msvc.log
)
dir bin >> build_msvc.log 2>&1

