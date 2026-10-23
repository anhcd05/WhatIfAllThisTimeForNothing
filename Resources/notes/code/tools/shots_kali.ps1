param([string]$Build, [string]$Bin, [string]$MapFile, [int]$Limit = 0, [string]$Only = '')
# Dieu phoi tren host: dung IDA tren Kali chup text + anh pseudo-code tung trang cho ban strip.
. 'C:\Users\xearh\AppData\Local\Temp\claude\E--CTF-2026-CyberSeaGame-2026-Resources\dfcef96c-f180-439b-8fcd-818c390f7dbd\scratchpad\vm.ps1'
Add-Type -AssemblyName System.Drawing
Add-Type -ReferencedAssemblies System.Drawing -TypeDefinition @"
using System; using System.Drawing; using System.Drawing.Imaging; using System.Runtime.InteropServices;
public static class Img {
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
$log = Join-Path $ns "shots_$Build.log"; if (-not $Only) { '' | Set-Content $log }
function Log($m) { "[$(Get-Date -f HH:mm:ss)] $m" | Add-Content $log }

# --- doc map: name addr ---
$mapPath = Join-Path $SD "maps_$Build.txt"
Kpull "/home/kali/algo_lab/maps/$MapFile" $mapPath | Out-Null
$want = 'a85_encode adler32_hash aes128_decrypt_block aes128_encrypt_block aes128_key_expand b32_encode b58_encode b64_decode b64_encode chacha20_block chacha20_xor crc32_bitwise crc32_table djb2_hash fnv1a_hash hex_encode md5_hash mix_chain op_add op_not op_reverse op_rol32 op_rol8 op_ror32 op_ror8 op_sub rc4_crypt rot13 salsa20_block salsa20_xor sha1_hash sha256_hash sha512_hash tea_decrypt tea_encrypt xor_repeat xor_single xtea_decrypt xtea_encrypt xxtea_decrypt xxtea_encrypt'.Split(' ')
$addr = @{}
foreach ($l in Get-Content $mapPath) { $p = $l.Trim().Split(' '); if ($p.Count -ge 2 -and $want -contains $p[0]) { $addr[$p[0]] = [Convert]::ToUInt64($p[1].Substring(2), 16) } }
if ($Only) { $want = $Only.Split(',') }
if ($Limit -gt 0) { $want = $want | Select-Object -First $Limit }
Log "map: $($addr.Count) functions"
# gop vao _map.txt (khong ghi de khi chay lai mot phan)
$mf = Join-Path $txtDir '_map.txt'; $mm = @{}
if (Test-Path $mf) { foreach ($l2 in Get-Content $mf) { $q = $l2.Trim().Split(' '); if ($q.Count -eq 2) { $mm[$q[0]] = $q[1] } } }
foreach ($n in $want) { $mm[$n] = "sub_{0:X}" -f $addr[$n] }
($mm.GetEnumerator() | Sort-Object Name | ForEach-Object { "{0} {1}" -f $_.Name, $_.Value }) | Set-Content $mf

# --- mo IDA, dong dock ---
Ksh @"
export DISPLAY=:0 XAUTHORITY=/home/kali/.Xauthority
xset s off; xset -dpms
pkill -TERM -x ida; sleep 2; pkill -KILL -x ida; sleep 1
mkdir -p /tmp/ida_work && cp ~/algo_lab/bin_s/$Bin /tmp/ida_work/
cd /tmp/ida_work; rm -f $Bin.i64 $Bin.id* $Bin.nam $Bin.til
setsid nohup /home/kali/ida-free-9.4/ida /tmp/ida_work/$Bin > /tmp/ida_shots.log 2>&1 < /dev/null &
sleep 12; xdotool key --clearmodifiers Return; sleep 90
xdotool mousemove 1651 731 click 1; sleep 1.5
xdotool mousemove 322 594 click 1; sleep 1.5
xdotool mousemove 322 184 click 1; sleep 1.5
xdotool mousemove 322 184 click 1; sleep 1.5
echo ready
"@ 'shopen' | Out-Null
Log "ida opened"

$done = 0
foreach ($n in $want) {
  $sub = "sub_{0:X}" -f $addr[$n]
  $ok = $false
  for ($try = 1; $try -le 3 -and -not $ok; $try++) {
    $w = 9 + 4 * ($try - 1)
    Ksh "export WAIT=$w; ~/algo_lab/s_gen.sh $sub ~/algo_lab/ps/$n.c" 'sg' | Out-Null
    $loc = Join-Path $txtDir "$n.c"; Remove-Item $loc -ErrorAction SilentlyContinue
    Kpull "/home/kali/algo_lab/ps/$n.c" $loc | Out-Null
    $head = ''; if (Test-Path $loc) { $head = (Get-Content $loc -TotalCount 3) -join ' ' }
    if ($head -match "\b$sub\b") { $ok = $true } else { Log "$n try $try invalid head: $($head.Substring(0,[Math]::Min(60,$head.Length)))"; Ksh '~/algo_lab/s_close.sh' 'sc' | Out-Null }
  }
  if (-not $ok) { Log "$n FAILED"; continue }
  $lines = (Get-Content $loc).Count
  $pages = [Math]::Max(1, [Math]::Ceiling($lines / 48))
  Ksh 'export DISPLAY=:0 XAUTHORITY=/home/kali/.Xauthority; xdotool key --clearmodifiers ctrl+Home; sleep 1' 'th' | Out-Null
  $files = @()
  for ($p = 1; $p -le $pages; $p++) {
    $fp = Join-Path $raw ("{0}_p{1}.png" -f $n, $p); Remove-Item $fp -ErrorAction SilentlyContinue
    & $v @KA captureScreen $K $fp 2>&1 | Out-Null
    $files += $fp
    if ($p -lt $pages) { Ksh '~/algo_lab/s_page.sh' 'sp' | Out-Null }
  }
  Ksh '~/algo_lab/s_close.sh' 'sc' | Out-Null
  $right = 0; foreach ($fp in $files) { $r = [Img]::RightMost($fp, 200, 832, 1640); if ($r -gt $right) { $right = $r } }
  $w = [Math]::Min(1670, [Math]::Max(640, $right + 28))
  $pn = 0; foreach ($fp in $files) { $pn++; [Img]::Crop($fp, (Join-Path $imgDir ("{0}_p{1}.png" -f $n, $pn)), 0, 168, $w, 684) }
  $done++
  Log ("{0} ok {1} lines {2} pages width {3}" -f $n, $lines, $pages, $w)
}
Ksh 'export DISPLAY=:0; pkill -TERM -x ida; sleep 2; pkill -KILL -x ida' 'shend' | Out-Null
Log "DONE $done/$($want.Count)"
'done' | Set-Content (Join-Path $ns "shots_${Build}.done")




