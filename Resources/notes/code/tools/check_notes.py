#!/usr/bin/env python3
"""
check_notes.py - kiem tra tu dong bo ghi chu (chay trong VM, khong chay tren may that):
  1) moi lien ket tuong doi [..](path) trong *.md tro toi file ton tai
  2) moi khoi ```python trong tung file md chay duoc (namespace SACH cho tung trang, chay theo thu tu
     -> phat hien khoi thieu import / ham phu tro khi copy-paste)
  3) moi khoi ```c tu ctfdec.h (co "ctf_"/"CTF_") bien dich duoc: gcc -fsyntax-only -Wall -Wextra
Chay (trong thu muc notes):   python code/tools/check_notes.py .
"""
import os
import re
import shutil
import subprocess
import sys
import tempfile
import traceback

root = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else ".")
mds = []
for d, _, fs in os.walk(root):
    for f in fs:
        if f.endswith(".md"):
            mds.append(os.path.join(d, f))
mds.sort()

bad_links = 0
link_re = re.compile(r"\]\(([^)#\s]+)(?:#[^)]*)?\)")
for p in mds:
    txt = open(p, encoding="utf-8").read()
    no_code = re.sub(r"```.*?```", "", txt, flags=re.S)
    for m in link_re.finditer(no_code):
        t = m.group(1)
        if t.startswith(("http://", "https://", "mailto:")):
            continue
        tgt = os.path.normpath(os.path.join(os.path.dirname(p), t))
        if not os.path.exists(tgt):
            bad_links += 1
            print("BROKEN LINK  %s -> %s" % (os.path.relpath(p, root), t))
print("links: %d broken" % bad_links)

fail = total = 0
for p in mds:
    txt = open(p, encoding="utf-8").read()
    blocks = re.findall(r"```python\n(.*?)```", txt, flags=re.S)
    ns = {"__name__": "mdcheck"}
    for i, b in enumerate(blocks, 1):
        total += 1
        try:
            exec(compile(b, "%s#py%d" % (os.path.relpath(p, root), i), "exec"), ns)
        except Exception:
            fail += 1
            print("PY FAIL  %s block %d" % (os.path.relpath(p, root), i))
            print("   " + traceback.format_exc().strip().splitlines()[-1])
print("python blocks: %d run, %d failed" % (total, fail))

cfail = ctotal = 0
gcc = shutil.which("gcc") or shutil.which("cc") or shutil.which("clang")
if gcc:
    for p in mds:
        txt = open(p, encoding="utf-8").read()
        for i, b in enumerate(re.findall(r"```c\n(.*?)```", txt, flags=re.S), 1):
            if not re.search(r"\b(ctf_|CTF_)", b) or "#include" not in b:
                continue
            ctotal += 1
            with tempfile.NamedTemporaryFile("w", suffix=".c", delete=False) as f:
                f.write(b + "\n")
                name = f.name
            r = subprocess.run([gcc, "-fsyntax-only", "-Wall", "-Wextra", "-Wno-unused-function", name],
                               capture_output=True, text=True)
            os.unlink(name)
            if r.returncode != 0 or "warning" in r.stderr:
                cfail += 1
                print("C FAIL  %s block %d\n%s" % (os.path.relpath(p, root), i, r.stderr[:400]))
    print("c blocks (ctfdec): %d compiled, %d failed" % (ctotal, cfail))
else:
    print("c blocks: gcc khong co, bo qua")
sys.exit(1 if (bad_links or fail or cfail) else 0)
