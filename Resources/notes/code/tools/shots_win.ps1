param([string]$Build, [string]$Bin, [string]$MapFile, [string]$Only = '')
# Dieu phoi tren host: dung IDA tren FlareVM chup text + anh pseudo-code tung trang (ban strip).
. 'C:\Users\xearh\AppData\Local\Temp\claude\E--CTF-2026-CyberSeaGame-2026-Resources\dfcef96c-f180-439b-8fcd-818c390f7dbd\scratchpad\vm.ps1'
Add-Type -AssemblyName System.Drawing
Add-Type -ReferencedAssemblies System.Drawing -TypeDefinition @"
using System; using System.Drawing; using System.Drawing.Imaging; using System.Runtime.InteropServices;
public static class ImgW {
  public static int RightMost(string path, int yTop, int yBot, int xMax) {
    using (var bmp = new Bitmap(path)) {
      var d = bmp.LockBits(new Rectangle(0,0,bmp.Width,bmp.Height), ImageLockMode.ReadOnly, PixelFormat.Format24bppRgb);
      int stride = d.Stride; byte[] buf = new byte[stride * bmp.Height];
      Marshal.Copy(d.Scan0, buf, 0, buf.Length); bmp.UnlockBits(d);
      int best = 0;
      for (int y = yTop; y < yBot; y++) { int row = y * stride;
        for (int x = xMax - 1; x > best; x--) { int i = row + x*3; if (buf[i] < 185 || buf[i+1] < 185 || buf[i+2] < 185) { best = x; break; } } }
      return best;
    }
  }
  public static void Crop(string src, string dst, int x, int y, int w, int h) {
    using (var bmp = new Bitmap(src)) using (var c = bmp.Clone(new Rectangle(x,y,w,h), bmp.PixelFormat)) c.Save(dst, ImageFormat.Png);
  }
}
"@
$ns = Join-Path $SD 'notes_src'
$txtDir = Join-Path $ns "pc\algos_${Build}_strip"; $imgDir = Join-Path $ns "img\${Build}_strip"
New-Item -ItemType Directory -Force $txtDir, $imgDir | Out-Null
$raw = Join-Path $SD "raw_$Build"; New-Item -ItemType Directory -Force $raw | Out-Null
$log = Join-Path $ns "shots_$Build.log"; '' | Set-Content $log
function Log($m) { "[$(Get-Date -f HH:mm:ss)] $m" | Add-Content $log }
function WStepB($steps) { & $v @FA runProgramInGuest $F -interactive $PSX -STA -NoProfile -ExecutionPolicy Bypass -File 'C:\Users\Public\algo_lab\win_step.ps1' -Steps $steps 2>&1 | Out-Null }

$want = 'a85_encode adler32_hash aes128_decrypt_block aes128_encrypt_block aes128_key_expand b32_encode b58_encode b64_decode b64_encode chacha20_block chacha20_xor crc32_bitwise crc32_table djb2_hash fnv1a_hash hex_encode md5_hash mix_chain op_add op_not op_reverse op_rol32 op_rol8 op_ror32 op_ror8 op_sub rc4_crypt rot13 salsa20_block salsa20_xor sha1_hash sha256_hash sha512_hash tea_decrypt tea_encrypt xor_repeat xor_single xtea_decrypt xtea_encrypt xxtea_decrypt xxtea_encrypt'.Split(' ')
$addr = @{}
foreach ($l in Get-Content (Join-Path $SD $MapFile)) { $pp = $l.Trim().Split(' '); if ($pp.Count -ge 2 -and $want -contains $pp[0]) { $addr[$pp[0]] = [Convert]::ToUInt64($pp[1].Substring(2), 16) } }
if ($Only) { $want = $Only.Split(',') }
Log "map: $($addr.Count) functions"
($want | ForEach-Object { "{0} sub_{1:X}" -f $_, $addr[$_] }) | Set-Content (Join-Path $txtDir '_map.txt')

# --- mo IDA (OpenOnly co PID guard) roi dong dock ---
& $v @FA runProgramInGuest $F -noWait -interactive $PSX -STA -NoProfile -ExecutionPolicy Bypass -File 'C:\Users\Public\algo_lab\ida_batch_win.ps1' -Bin "C:\Users\Public\algo_lab\bin_s\$Bin" -OutDir "C:\Users\Public\algo_lab\pc\tmp_$Build" -OpenOnly 2>&1 | Out-Null
Start-Sleep -Seconds 80
$pidok = (Fps 'Get-Content C:\Users\Public\ida_pid.txt' 'pidchk') -join ' '
Log "ida pid file: $pidok"
Fps 'Remove-Item C:\Users\Public\step_log.txt -ErrorAction SilentlyContinue' 'rmlog' | Out-Null
WStepB 'click 1652 694; sleep 1; click 315 524; sleep 1; click 315 173; sleep 1; click 315 173; sleep 1; click 165 170; sleep 1'
Log "docks closed"

$done = 0
foreach ($n in $want) {
  $sub = "sub_{0:X}" -f $addr[$n]
  $ok = $false
  for ($try = 1; $try -le 3 -and -not $ok; $try++) {
    $w = 10 + 4 * ($try - 1)
    Fps 'Remove-Item C:\Users\Public\algo_lab\cur.c -ErrorAction SilentlyContinue' 'rmc' | Out-Null
    WStepB "click 165 170; click 900 450; keys g; sleep 2; keys $sub; sleep 3; keys {ENTER}; sleep 2; click 235 42; click 300 74; click 734 172; sleep $w; click 1000 450; copy C:\Users\Public\algo_lab\cur.c; click 1000 450; keys ^{HOME}; sleep 1"
    $loc = Join-Path $txtDir "$n.c"; Remove-Item $loc -ErrorAction SilentlyContinue
    Fpull 'C:\Users\Public\algo_lab\cur.c' $loc | Out-Null
    $head = ''; if (Test-Path $loc) { $head = (Get-Content $loc -TotalCount 3) -join ' ' }
    if ($head -match "\b$sub\b") { $ok = $true } else { Log "$n try $try invalid head: $($head.Substring(0,[Math]::Min(60,$head.Length)))"; WStepB 'click 530 169; sleep 1' }
  }
  if (-not $ok) { Log "$n FAILED"; continue }
  $lines = (Get-Content $loc).Count
  $pages = [Math]::Max(1, [Math]::Ceiling($lines / 29))
  $files = @()
  for ($p = 1; $p -le $pages; $p++) {
    $fp = Join-Path $raw ("{0}_p{1}.png" -f $n, $p); Remove-Item $fp -ErrorAction SilentlyContinue
    & $v @FA captureScreen $F $fp 2>&1 | Out-Null
    $files += $fp
    if ($p -lt $pages) { WStepB 'keys {PGDN}; sleep 1' }
  }
  WStepB 'click 530 169; sleep 1'
  $right = 0; foreach ($fp in $files) { $r = [ImgW]::RightMost($fp, 186, 778, 1660); if ($r -gt $right) { $right = $r } }
  $cw = [Math]::Min(1670, [Math]::Max(640, $right + 28))
  $pn = 0; foreach ($fp in $files) { $pn++; [ImgW]::Crop($fp, (Join-Path $imgDir ("{0}_p{1}.png" -f $n, $pn)), 0, 157, $cw, 648) }
  $done++
  Log ("{0} ok {1} lines {2} pages width {3}" -f $n, $lines, $pages, $cw)
}
Get-CimInstance Win32_Process -Filter "name='ida.exe'" -ErrorAction SilentlyContinue | Out-Null
Fps 'Get-CimInstance Win32_Process -Filter "name=''ida.exe''" | Where-Object { $_.CommandLine -like ''*ida_work2*'' } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force }' 'killmine' | Out-Null
Log "DONE $done/$($want.Count)"
'done' | Set-Content (Join-Path $ns "shots_${Build}.done")
