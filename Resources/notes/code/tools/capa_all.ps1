$d = 'C:\Users\Public\algo_lab'
foreach ($n in 'algos_msvc_Od.exe','algos_gcc_O2','algos_gcc_O0','algos_mingw_O2.exe','algos_mingw_O0.exe') {
  & 'C:\Tools\capa\capa.exe' -q "$d\bin\$n" 2>&1 | Out-File -Encoding utf8 "$d\capa_$n.txt"
}
'done' | Set-Content "$d\capa_alldone"
