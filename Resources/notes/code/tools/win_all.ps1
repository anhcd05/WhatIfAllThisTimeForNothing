$d = 'C:\Users\Public\algo_lab'
foreach ($n in 'algos_msvc_Od','algos_msvc_O2') {
  Start-Process powershell.exe -Wait -ArgumentList @('-STA','-NoProfile','-ExecutionPolicy','Bypass','-File',"$d\ida_batch_win.ps1",'-Bin',"$d\bin\$n.exe",'-OutDir',"$d\pc\$n")
}
'done' | Set-Content "$d\pc\_win_alldone"
