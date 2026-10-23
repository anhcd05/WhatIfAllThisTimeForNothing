param([string]$Steps)   # vi du: "click 420 170; keys g; keys b64_encode; keys {ENTER}; sleep 2"
Add-Type -TypeDefinition @"
using System; using System.Runtime.InteropServices;
public class W {
  [DllImport("user32.dll")] public static extern bool SetProcessDPIAware();
  [DllImport("user32.dll")] public static extern bool SetCursorPos(int x,int y);
  [DllImport("user32.dll")] public static extern void mouse_event(uint f,uint dx,uint dy,uint d,UIntPtr e);
  [DllImport("user32.dll")] public static extern IntPtr GetForegroundWindow();
  [DllImport("user32.dll")] public static extern int GetWindowThreadProcessId(IntPtr h, out int pid);
  [DllImport("user32.dll")] public static extern IntPtr WindowFromPoint(int x, int y);
  [DllImport("user32.dll")] public static extern IntPtr GetAncestor(IntPtr h, uint f);
  public static int PidOf(IntPtr h){ int p; GetWindowThreadProcessId(h, out p); return p; }
  public static int PidAt(int x,int y){ IntPtr h = WindowFromPoint(x,y); if (h==IntPtr.Zero) return -1; return PidOf(GetAncestor(h,2)); }
  public static int FgPid(){ return PidOf(GetForegroundWindow()); }
}
"@
[void][W]::SetProcessDPIAware()
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName Microsoft.VisualBasic
$mypid = [int](Get-Content 'C:\Users\Public\ida_pid.txt')
$log = 'C:\Users\Public\step_log.txt'
function Log($m){ "[$(Get-Date -f HH:mm:ss)] $m" | Add-Content $log }
for ($i=0; $i -lt 6 -and [W]::FgPid() -ne $mypid; $i++) { try { [Microsoft.VisualBasic.Interaction]::AppActivate($mypid) } catch {}; Start-Sleep -Milliseconds 700 }
if ([W]::FgPid() -ne $mypid) { Log "ABORT fg=$([W]::FgPid()) mine=$mypid"; exit 2 }
foreach ($st in $Steps.Split(';')) {
  $st = $st.Trim(); if (-not $st) { continue }
  $a = $st.Split(' ', 2)
  switch ($a[0]) {
    'click' { $xy = $a[1].Split(' '); $x=[int]$xy[0]; $y=[int]$xy[1]; [void][W]::SetCursorPos($x,$y); Start-Sleep -Milliseconds 300
              if ([W]::PidAt($x,$y) -ne $mypid) { Log "ABORT click ($x,$y) pid=$([W]::PidAt($x,$y))"; exit 2 }
              [W]::mouse_event(2,0,0,0,[UIntPtr]::Zero); Start-Sleep -Milliseconds 100; [W]::mouse_event(4,0,0,0,[UIntPtr]::Zero); Start-Sleep -Milliseconds 800 }
    'keys'  { if ([W]::FgPid() -ne $mypid) { Log "ABORT keys fg=$([W]::FgPid())"; exit 2 }; [System.Windows.Forms.SendKeys]::SendWait($a[1]); Start-Sleep -Milliseconds 800 }
    'sleep' { Start-Sleep -Seconds ([int]$a[1]) }
    'copy'  { [System.Windows.Forms.Clipboard]::Clear(); if ([W]::FgPid() -ne $mypid) { Log "ABORT copy fg"; exit 2 }
              [System.Windows.Forms.SendKeys]::SendWait('^a'); Start-Sleep -Milliseconds 400; [System.Windows.Forms.SendKeys]::SendWait('^c'); Start-Sleep -Milliseconds 700
              $t = [System.Windows.Forms.Clipboard]::GetText(); Set-Content $a[1] $t -Encoding utf8; Log "copied $($t.Length) chars to $($a[1])" }
  }
}
Log "steps done: $Steps"
