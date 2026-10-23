# Helper dot-source: . vm.ps1
$v = 'C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe'; if (-not (Test-Path $v)) { $v = 'C:\Program Files\VMware\VMware Workstation\vmrun.exe' }
$K = 'E:\Kali\kali-linux-2026.2-vmware-amd64\kali-linux-2026.2-vmware-amd64.vmwarevm\kali-linux-2026.2-vmware-amd64.vmx'
$F = 'E:\VMs\FlareVM\FlareVM.vmx'
$KA = @('-T','ws','-gu','kali','-gp','<KALI_PASSWORD>')
$FA = @('-T','ws','-gu','analyst','-gp','<FLARE_PASSWORD>')
$SD = 'C:\Users\xearh\AppData\Local\Temp\claude\E--CTF-2026-CyberSeaGame-2026-Resources\dfcef96c-f180-439b-8fcd-818c390f7dbd\scratchpad'
$PSX = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'

function Kpush($local, $remote) { & $v @KA CopyFileFromHostToGuest $K $local $remote 2>&1 }
function Kpull($remote, $local) { & $v @KA CopyFileFromGuestToHost $K $remote $local 2>&1 }
function Fpush($local, $remote) { & $v @FA CopyFileFromHostToGuest $F $local $remote 2>&1 }
function Fpull($remote, $local) { & $v @FA CopyFileFromGuestToHost $F $remote $local 2>&1 }

# chay doan bash tren Kali, stdout+stderr ghi ve host
function Ksh([string]$body, [string]$tag = 'k') {
  $lp = Join-Path $SD "_$tag.sh"
  ("#!/bin/bash`nexec > /tmp/_$tag.out 2>&1`n" + $body + "`n") -replace "`r`n","`n" | Set-Content $lp -Encoding ascii -NoNewline
  Kpush $lp "/tmp/_$tag.sh" | Out-Null
  & $v @KA runScriptInGuest $K /bin/bash "/bin/bash /tmp/_$tag.sh" 2>&1 | Out-Null
  $o = Join-Path $SD "_$tag.out"; Remove-Item $o -ErrorAction SilentlyContinue
  Kpull "/tmp/_$tag.out" $o | Out-Null
  if (Test-Path $o) { Get-Content $o }
}

# chay doan PowerShell tren FlareVM (non-interactive), output ghi ve host
function Fps([string]$body, [string]$tag = 'f') {
  $lp = Join-Path $SD "_$tag.ps1"
  ('& {' + "`r`n" + $body + "`r`n" + '} 2>&1 | Out-File -Encoding ascii C:\Users\Public\_' + $tag + '.out' + "`r`n") | Set-Content $lp -Encoding ascii
  Fpush $lp "C:\Users\Public\_$tag.ps1" | Out-Null
  & $v @FA runProgramInGuest $F $PSX -NoProfile -ExecutionPolicy Bypass -File "C:\Users\Public\_$tag.ps1" 2>&1 | Out-Null
  $o = Join-Path $SD "_$tag.out"; Remove-Item $o -ErrorAction SilentlyContinue
  Fpull "C:\Users\Public\_$tag.out" $o | Out-Null
  if (Test-Path $o) { Get-Content $o }
}

function Shot($vmx, $args_, $name) {
  $png = Join-Path $SD $name; Remove-Item $png -ErrorAction SilentlyContinue
  & $v @args_ captureScreen $vmx $png 2>&1 | Out-Null
  return $png
}

