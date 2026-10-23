param([string]$Build, [ValidateSet('kali','win')][string]$Kind)
# Cat lai anh tu anh tho (bo duong vien xam o dau vung noi dung), bang vung co chieu rong theo noi dung that.
$SD = 'C:\Users\xearh\AppData\Local\Temp\claude\E--CTF-2026-CyberSeaGame-2026-Resources\dfcef96c-f180-439b-8fcd-818c390f7dbd\scratchpad'
Add-Type -AssemblyName System.Drawing
Add-Type -ReferencedAssemblies System.Drawing -TypeDefinition @"
using System; using System.Drawing; using System.Drawing.Imaging; using System.Runtime.InteropServices;
public static class ImgR {
  public static int RightMost(string path, int yTop, int yBot, int xMax) {
    using (var bmp = new Bitmap(path)) {
      var d = bmp.LockBits(new Rectangle(0,0,bmp.Width,bmp.Height), ImageLockMode.ReadOnly, PixelFormat.Format24bppRgb);
      int stride = d.Stride; byte[] buf = new byte[stride * bmp.Height];
      Marshal.Copy(d.Scan0, buf, 0, buf.Length); bmp.UnlockBits(d);
      int best = 0;
      for (int y = yTop; y < yBot; y++) { int row = y * stride;
        for (int x = xMax - 1; x > best; x--) { int i = row + x*3; if (buf[i] < 160 || buf[i+1] < 160 || buf[i+2] < 160) { best = x; break; } } }
      return best;
    }
  }
  public static int BottomMost(string path, int yTop, int yBot, int xMax) {
    using (var bmp = new Bitmap(path)) {
      var d = bmp.LockBits(new Rectangle(0,0,bmp.Width,bmp.Height), ImageLockMode.ReadOnly, PixelFormat.Format24bppRgb);
      int stride = d.Stride; byte[] buf = new byte[stride * bmp.Height];
      Marshal.Copy(d.Scan0, buf, 0, buf.Length); bmp.UnlockBits(d);
      for (int y = yBot - 1; y >= yTop; y--) { int row = y * stride;
        for (int x = 12; x < xMax; x++) { int i = row + x*3; if (buf[i] < 160 || buf[i+1] < 160 || buf[i+2] < 160) return y; } }
      return yTop;
    }
  }
  public static void Crop(string src, string dst, int x, int y, int w, int h) {
    using (var bmp = new Bitmap(src)) using (var c = bmp.Clone(new Rectangle(x,y,w,h), bmp.PixelFormat)) c.Save(dst, ImageFormat.Png);
  }
}
"@
if ($Kind -eq 'kali') { $yTop = 206; $yBot = 830; $xMax = 1640; $cy = 168; $ch = 684 } else { $yTop = 192; $yBot = 776; $xMax = 1662; $cy = 157; $ch = 648 }
$raw = Join-Path $SD "raw_$Build"; $imgDir = Join-Path $SD "notes_src\img\${Build}_strip"
$groups = Get-ChildItem $imgDir -Filter *.png | ForEach-Object { if ($_.Name -match '^(.+)_p(\d+)\.png$') { [pscustomobject]@{ n = $matches[1]; p = [int]$matches[2] } } } | Group-Object n
$tot = 0
foreach ($g in $groups) {
  $files = $g.Group | Sort-Object p | ForEach-Object { Join-Path $raw ("{0}_p{1}.png" -f $g.Name, $_.p) }
  if (($files | Where-Object { -not (Test-Path $_) }).Count) { "skip $($g.Name): raw missing"; continue }
  $right = 0; foreach ($fp in $files) { $r = [ImgR]::RightMost($fp, $yTop, $yBot, $xMax); if ($r -gt $right) { $right = $r } }
  $cw = [Math]::Min(1670, [Math]::Max(560, $right + 30))
  $i = 0; foreach ($fp in $files) { $i++; $bt = [ImgR]::BottomMost($fp, $yTop, $yBot, $cw); $hh = [Math]::Min($ch, [Math]::Max(140, $bt + 22 - $cy)); [ImgR]::Crop($fp, (Join-Path $imgDir ("{0}_p{1}.png" -f $g.Name, $i)), 0, $cy, $cw, $hh); $tot++ }
}
"recropped $tot images for $Build"


