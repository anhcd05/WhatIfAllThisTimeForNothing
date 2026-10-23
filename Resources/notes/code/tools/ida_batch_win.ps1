param([string]$Bin, [string]$OutDir, [int]$ExtraWait = 15, [string]$Only = '', [switch]$OpenOnly)
Add-Type -TypeDefinition @"
using System; using System.Collections.Generic; using System.Runtime.InteropServices; using System.Text;
public class W {
  public delegate bool EnumProc(IntPtr h, IntPtr l);
  [DllImport("user32.dll")] public static extern bool SetProcessDPIAware();
  [DllImport("user32.dll")] public static extern bool SetCursorPos(int x,int y);
  [DllImport("user32.dll")] public static extern void mouse_event(uint f,uint dx,uint dy,uint d,UIntPtr e);
  [DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc p, IntPtr l);
  [DllImport("user32.dll")] public static extern int GetWindowText(IntPtr h, StringBuilder s, int n);
  [DllImport("user32.dll")] public static extern int GetWindowThreadProcessId(IntPtr h, out int pid);
  [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr h, int c);
  [DllImport("user32.dll")] public static extern IntPtr GetForegroundWindow();
  [DllImport("user32.dll")] public static extern IntPtr WindowFromPoint(int x, int y);
  [DllImport("user32.dll")] public static extern IntPtr GetAncestor(IntPtr h, uint f);
  public static int PidOf(IntPtr h){ int p; GetWindowThreadProcessId(h, out p); return p; }
  public static string Title(IntPtr h){ var sb = new StringBuilder(512); GetWindowText(h, sb, 512); return sb.ToString(); }
  public static List<IntPtr> Wins(int pid){ var l = new List<IntPtr>(); EnumWindows((h, x) => { if (IsWindowVisible(h) && PidOf(h) == pid) l.Add(h); return true; }, IntPtr.Zero); return l; }
  public static int PidAt(int x, int y){ IntPtr h = WindowFromPoint(x, y); if (h == IntPtr.Zero) return -1; h = GetAncestor(h, 2); return PidOf(h); }
  public static int FgPid(){ return PidOf(GetForegroundWindow()); }
}
"@
[void][W]::SetProcessDPIAware()
Add-Type -AssemblyName System.Windows.Forms
$script:MyPid = 0
$name0 = [IO.Path]::GetFileName($Bin)
$work = 'C:\Users\Public\ida_work2'
New-Item -ItemType Directory -Force $OutDir | Out-Null
$log = Join-Path $OutDir '_log.txt'; '' | Set-Content $log
function Log($m){ "[$(Get-Date -f HH:mm:ss)] $m" | Add-Content $log }
function Abort($m){ Log "ABORT: $m"; Get-Process -Id $script:MyPid -ErrorAction SilentlyContinue | Stop-Process -Force; exit 2 }
Add-Type -AssemblyName Microsoft.VisualBasic
function Fg($contains){
  for ($i = 0; $i -lt 8; $i++) {
    if ([W]::FgPid() -eq $script:MyPid) { return }
    try { [Microsoft.VisualBasic.Interaction]::AppActivate($script:MyPid) } catch {}
    Start-Sleep -Milliseconds 600
    if ([W]::FgPid() -eq $script:MyPid) { return }
    foreach ($h in [W]::Wins($script:MyPid)) {
      $t = [W]::Title($h)
      if ($t -like "*$contains*") { [void][W]::ShowWindow($h, 6); Start-Sleep -Milliseconds 300; [void][W]::ShowWindow($h, 9); [void][W]::SetForegroundWindow($h); Start-Sleep -Milliseconds 600 }
    }
    if ([W]::FgPid() -eq $script:MyPid) { return }
  }
  Abort "foreground pid $([W]::FgPid()) != my pid $($script:MyPid) (looking for '$contains')"
}
function Click($x,$y,$wait=900){
  [void][W]::SetCursorPos($x,$y); Start-Sleep -Milliseconds 300
  if ([W]::PidAt($x,$y) -ne $script:MyPid) { Abort "click at ($x,$y) would hit pid $([W]::PidAt($x,$y)), not mine" }
  [W]::mouse_event(2,0,0,0,[UIntPtr]::Zero); Start-Sleep -Milliseconds 100; [W]::mouse_event(4,0,0,0,[UIntPtr]::Zero); Start-Sleep -Milliseconds $wait
}
function Keys($s,$wait=800){
  if ([W]::FgPid() -ne $script:MyPid) { Abort "keys '$s' but foreground is pid $([W]::FgPid())" }
  [System.Windows.Forms.SendKeys]::SendWait($s); Start-Sleep -Milliseconds $wait
}

# chi tat IDA do chinh minh mo truoc do
Get-CimInstance Win32_Process -Filter "name='ida.exe'" | Where-Object { $_.CommandLine -like '*ida_work2*' } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
Start-Sleep -Seconds 2
New-Item -ItemType Directory -Force $work | Out-Null
Get-ChildItem $work -Filter "$name0*" -ErrorAction SilentlyContinue | Where-Object { $_.Extension -in '.i64','.id0','.id1','.id2','.nam','.til' } | Remove-Item -Force -ErrorAction SilentlyContinue
Copy-Item $Bin (Join-Path $work $name0) -Force
$proc = Start-Process 'C:\Program Files\IDA Free 9.4\ida.exe' -ArgumentList ('"' + (Join-Path $work $name0) + '"') -PassThru
$script:MyPid = $proc.Id
Log "launched pid $($script:MyPid)"

# cho + tra loi hop thoai cua chinh PID nay (Load a new file / Load PDB file) cho den khi cua so chinh san sang
$ready = $false; $deadline = (Get-Date).AddSeconds(240); $stable = 0
while ((Get-Date) -lt $deadline) {
  Start-Sleep -Seconds 2
  if (-not (Get-Process -Id $script:MyPid -ErrorAction SilentlyContinue)) { Abort "my IDA exited" }
  $titles = @([W]::Wins($script:MyPid) | ForEach-Object { [W]::Title($_) })
  if ($titles -contains 'Load a new file') { Fg 'Load a new file'; Keys '{ENTER}' 3000; Log 'answered Load dialog'; $stable = 0; continue }
  if ($titles -contains 'Load PDB file')   { Fg 'Load PDB file';   Keys '{ENTER}' 3000; Log 'answered PDB dialog';  $stable = 0; continue }
  $main = $titles | Where-Object { $_ -like 'IDA - *' } | Select-Object -First 1
  if ($main -and $main -notlike '*Loading*') { $stable++ } else { $stable = 0 }
  if ($stable -ge 5) { $ready = $true; break }
}
if (-not $ready) { Abort 'IDA never became ready' }
Log "ready; extra wait $ExtraWait s"
Start-Sleep -Seconds $ExtraWait
 if ($OpenOnly) { $script:MyPid | Set-Content 'C:\Users\Public\ida_pid.txt'; Log 'OpenOnly: leaving IDA open'; exit 0 }

$stem = [IO.Path]::GetFileNameWithoutExtension($Bin)
$fns = 'a85_encode adler32_hash aes128_decrypt_block aes128_encrypt_block aes128_key_expand b32_encode b58_encode b64_decode b64_encode chacha20_block chacha20_xor crc32_bitwise crc32_table djb2_hash fnv1a_hash hex_encode main md5_hash mix_chain op_add op_not op_reverse op_rol32 op_rol8 op_ror32 op_ror8 op_sub rc4_crypt rot13 salsa20_block salsa20_xor sha1_hash sha256_hash sha512_hash tea_decrypt tea_encrypt xor_repeat xor_single xtea_decrypt xtea_encrypt xxtea_decrypt xxtea_encrypt gm xt'.Split(' ')
if ($Only) { $fns = $Only.Split(',') }
foreach ($n in $fns) {
  $out = Join-Path $OutDir "$n.c"; Remove-Item $out -ErrorAction SilentlyContinue
  [System.Windows.Forms.Clipboard]::Clear()
  Fg "IDA - $stem"
  Click 420 170 600
  Keys 'g' 1500
  Keys $n 2500
  Keys '{ENTER}' 1500
  Fg "IDA - $stem"
  Click 235 42 800; Click 300 74 800; Click 734 172 7000
  $ok = 0
  for ($t = 1; $t -le 5; $t++) {
    Fg "IDA - $stem"
    Click 1000 450 500
    Keys '^a' 400; Keys '^c' 700
    $txt = ''
    try { $txt = [System.Windows.Forms.Clipboard]::GetText() } catch {}
    if ($txt) { Set-Content $out $txt -Encoding utf8 }
    if ($txt -and (($txt -split "`n" | Select-Object -First 3) -join ' ') -match "\b$n\b") { $ok = 1; break }
    Start-Sleep -Seconds 6
  }
  Log "$n ok=$ok bytes=$((Get-Item $out -ErrorAction SilentlyContinue).Length)"
}
Log "done $name0"
Get-Process -Id $script:MyPid -ErrorAction SilentlyContinue | Stop-Process -Force



