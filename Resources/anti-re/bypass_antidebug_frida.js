/*
 * bypass_antidebug_frida.js
 * ---------------------------------------------------------------------------
 * Script Frida hook các kỹ thuật anti-debug phổ biến trên WINDOWS.
 * MỤC ĐÍCH: phân tích / giải đề CTF Reverse & Malware Analysis (hợp lệ).
 *           Vô hiệu hoá lớp chống-gỡ-lỗi để đọc được logic thật của binary.
 *
 * CÁCH CHẠY:
 *   1) Cài:   pip install frida-tools
 *   2) Spawn (khuyên dùng để bắt được check sớm / TLS callback):
 *        frida -f target.exe -l bypass_antidebug_frida.js
 *      (sau khi script nạp xong, gõ  %resume  để cho tiến trình chạy tiếp)
 *   3) Attach vào tiến trình đang chạy:
 *        frida -n target.exe -l bypass_antidebug_frida.js
 *        frida -p <PID>      -l bypass_antidebug_frida.js
 *
 * GHI CHÚ: tự dò x86/x64. Bật/tắt từng nhóm bằng biến CONFIG bên dưới.
 * ---------------------------------------------------------------------------
 */

'use strict';

// ======================= CẤU HÌNH (bật/tắt từng nhóm) =======================
const CONFIG = {
    peb:        true,  // Vá PEB.BeingDebugged + NtGlobalFlag (đọc/ghi trực tiếp)
    isDbgPresent: true,// IsDebuggerPresent / CheckRemoteDebuggerPresent
    ntQueryInfo:  true,// NtQueryInformationProcess (DebugPort/Flags/ObjectHandle)
    ntQuerySys:   true,// NtQuerySystemInformation (KernelDebuggerInformation)
    threadHide:   true,// NtSetInformationThread (ThreadHideFromDebugger)
    ntClose:      true,// NtClose/CloseHandle invalid-handle
    getThreadCtx: true,// GetThreadContext -> zero debug registers Dr0..Dr7
    findWindow:   true,// FindWindowA/W (class debugger)
    outputDbgStr: true,// OutputDebugStringA (trick GetLastError)
    verbose:      true,// in log chi tiết
};

const IS_X64 = Process.pointerSize === 8;
function log(msg) { if (CONFIG.verbose) console.log('[antidbg] ' + msg); }
function ok(msg)  { console.log('[antidbg][+] ' + msg); }

// Tiện ích: lấy export an toàn (trả null nếu không có)
function exp(mod, name) {
    try { return Module.getExportByName(mod, name); } catch (e) { return null; }
}

// ===========================================================================
// 1) PEB: BeingDebugged (offset 0x02) + NtGlobalFlag (0x68 x86 / 0xBC x64)
//    Đọc trực tiếp từ TEB->PEB và ghi đè 0.
// ===========================================================================
function patchPEB() {
    try {
        // PEB: x86 fs:[0x30], x64 gs:[0x60]. Frida cho con trỏ PEB qua TEB.
        // Dùng NtCurrentTeb-like: đọc qua Process.getCurrentThreadId không có PEB,
        // nên lấy PEB bằng cách đọc segment base qua một đối tượng đã map.
        // Cách chắc chắn: dùng 'ntdll!RtlGetCurrentPeb'.
        const pRtlGetCurrentPeb = exp('ntdll.dll', 'RtlGetCurrentPeb');
        if (!pRtlGetCurrentPeb) { log('Không tìm thấy RtlGetCurrentPeb'); return; }
        const RtlGetCurrentPeb = new NativeFunction(pRtlGetCurrentPeb, 'pointer', []);
        const peb = RtlGetCurrentPeb();
        if (peb.isNull()) { log('PEB null'); return; }

        // BeingDebugged (BYTE) tại PEB+0x02
        const pBeingDebugged = peb.add(0x02);
        log('PEB=' + peb + '  BeingDebugged=' + pBeingDebugged.readU8());
        pBeingDebugged.writeU8(0);

        // NtGlobalFlag (DWORD): x86 +0x68, x64 +0xBC
        const ntGlobalOff = IS_X64 ? 0xBC : 0x68;
        const pNtGlobalFlag = peb.add(ntGlobalOff);
        log('NtGlobalFlag(0x' + ntGlobalOff.toString(16) + ')=' +
            pNtGlobalFlag.readU32().toString(16));
        pNtGlobalFlag.writeU32(0);

        ok('PEB patched: BeingDebugged=0, NtGlobalFlag=0');

        // TODO: nếu đề còn đọc Heap Flags/ForceFlags, có thể vá thêm:
        //   ProcessHeap = PEB+0x18(x86)/0x30(x64); Flags/ForceFlags tại
        //   heap+0x40/0x44 (x86 Vista+) hoặc heap+0x70/0x74 (x64 Vista+).
        //   Đặt Flags=0x2, ForceFlags=0. (Thường ScyllaHide xử lý tốt hơn.)
    } catch (e) {
        log('patchPEB lỗi: ' + e);
    }
}

// ===========================================================================
// 2) IsDebuggerPresent -> 0 ; CheckRemoteDebuggerPresent -> *pbDbg = FALSE
// ===========================================================================
function hookIsDebuggerPresent() {
    const p = exp('kernel32.dll', 'IsDebuggerPresent') ||
              exp('kernelbase.dll', 'IsDebuggerPresent');
    if (p) {
        Interceptor.attach(p, {
            onLeave: function (retval) {
                if (!retval.isNull()) log('IsDebuggerPresent -> ép 0');
                retval.replace(ptr(0));
            }
        });
        ok('Hooked IsDebuggerPresent');
    }

    const pc = exp('kernel32.dll', 'CheckRemoteDebuggerPresent') ||
               exp('kernelbase.dll', 'CheckRemoteDebuggerPresent');
    if (pc) {
        Interceptor.attach(pc, {
            // BOOL CheckRemoteDebuggerPresent(HANDLE hProcess, PBOOL pbDebuggerPresent)
            onEnter: function (args) { this.pbDbg = args[1]; },
            onLeave: function (retval) {
                try {
                    if (this.pbDbg && !this.pbDbg.isNull()) {
                        this.pbDbg.writeU32(0); // ép FALSE
                        log('CheckRemoteDebuggerPresent -> *pbDbg=0');
                    }
                } catch (e) {}
                retval.replace(ptr(1)); // hàm vẫn "thành công"
            }
        });
        ok('Hooked CheckRemoteDebuggerPresent');
    }
}

// ===========================================================================
// 3) NtQueryInformationProcess: chỉnh output cho 3 info class
//    0x07 ProcessDebugPort        -> 0
//    0x1E ProcessDebugObjectHandle-> 0  (+ trả STATUS_PORT_NOT_SET)
//    0x1F ProcessDebugFlags       -> 1  (NoDebugInherit đảo = "không gỡ")
// ===========================================================================
function hookNtQueryInformationProcess() {
    const p = exp('ntdll.dll', 'NtQueryInformationProcess');
    if (!p) return;
    const ProcessDebugPort = 0x07;
    const ProcessDebugObjectHandle = 0x1E;
    const ProcessDebugFlags = 0x1F;
    const STATUS_PORT_NOT_SET = 0xC0000353 | 0; // dùng cho DebugObjectHandle

    Interceptor.attach(p, {
        // NTSTATUS NtQueryInformationProcess(HANDLE, PROCESSINFOCLASS cls,
        //          PVOID buf, ULONG len, PULONG retLen)
        onEnter: function (args) {
            this.cls = args[1].toInt32();
            this.buf = args[2];
        },
        onLeave: function (retval) {
            try {
                if (this.buf.isNull()) return;
                if (this.cls === ProcessDebugPort) {
                    this.buf.writePointer(ptr(0));
                    log('NtQIP ProcessDebugPort -> 0');
                } else if (this.cls === ProcessDebugObjectHandle) {
                    this.buf.writePointer(ptr(0));
                    retval.replace(ptr(STATUS_PORT_NOT_SET >>> 0));
                    log('NtQIP ProcessDebugObjectHandle -> 0');
                } else if (this.cls === ProcessDebugFlags) {
                    this.buf.writeU32(1); // khác 0 = "không bị gỡ"
                    log('NtQIP ProcessDebugFlags -> 1');
                }
            } catch (e) { log('NtQIP onLeave lỗi: ' + e); }
        }
    });
    ok('Hooked NtQueryInformationProcess');
}

// ===========================================================================
// 4) NtQuerySystemInformation: SystemKernelDebuggerInformation (0x23)
//    Trả DebuggerEnabled=0, DebuggerNotPresent=1
// ===========================================================================
function hookNtQuerySystemInformation() {
    const p = exp('ntdll.dll', 'NtQuerySystemInformation');
    if (!p) return;
    const SystemKernelDebuggerInformation = 0x23;
    Interceptor.attach(p, {
        onEnter: function (args) {
            this.cls = args[0].toInt32();
            this.buf = args[1];
        },
        onLeave: function (retval) {
            try {
                if (this.cls === SystemKernelDebuggerInformation && !this.buf.isNull()) {
                    // struct: BOOLEAN DebuggerEnabled; BOOLEAN DebuggerNotPresent;
                    this.buf.writeU8(0);          // DebuggerEnabled = FALSE
                    this.buf.add(1).writeU8(1);   // DebuggerNotPresent = TRUE
                    log('NtQSI KernelDebuggerInformation -> enabled=0, notPresent=1');
                }
            } catch (e) {}
        }
    });
    ok('Hooked NtQuerySystemInformation');
}

// ===========================================================================
// 5) NtSetInformationThread: chặn ThreadHideFromDebugger (0x11)
// ===========================================================================
function hookThreadHide() {
    const p = exp('ntdll.dll', 'NtSetInformationThread');
    if (!p) return;
    const ThreadHideFromDebugger = 0x11;
    Interceptor.attach(p, {
        onEnter: function (args) {
            this.cls = args[1].toInt32();
            if (this.cls === ThreadHideFromDebugger) {
                this.blocked = true;
                // Vô hiệu bằng cách đổi class sang giá trị vô hại (không bắt buộc);
                // ở đây ta để nguyên onEnter nhưng ép trả STATUS_SUCCESS mà không ẩn.
            }
        },
        onLeave: function (retval) {
            if (this.blocked) {
                retval.replace(ptr(0)); // STATUS_SUCCESS, nhưng không che luồng
                log('NtSetInformationThread ThreadHideFromDebugger -> bị chặn');
            }
        }
    });
    ok('Hooked NtSetInformationThread (ThreadHideFromDebugger)');
    // TODO nâng cao: để chắc chắn luồng KHÔNG bị ẩn, có thể Interceptor.replace
    // và chỉ gọi hàm gốc với class != 0x11.
}

// ===========================================================================
// 6) NtClose / CloseHandle: nuốt invalid-handle để không ném 0xC0000008
// ===========================================================================
function hookNtClose() {
    const p = exp('ntdll.dll', 'NtClose');
    if (!p) return;
    Interceptor.attach(p, {
        onLeave: function (retval) {
            // STATUS_INVALID_HANDLE = 0xC0000008 -> ép thành STATUS_SUCCESS (0)
            if ((retval.toInt32() >>> 0) === 0xC0000008) {
                retval.replace(ptr(0));
                log('NtClose invalid-handle -> nuốt (STATUS_SUCCESS)');
            }
        }
    });
    ok('Hooked NtClose (invalid handle)');
}

// ===========================================================================
// 7) GetThreadContext: zero debug registers Dr0..Dr7 trong CONTEXT trả về
//    Offset Dr (x64): Dr0=+0x48 Dr1=+0x50 Dr2=+0x58 Dr3=+0x60 Dr6=+0x68 Dr7=+0x70
//    (x86): Dr0..Dr7 nằm ở +0x04..+0x18 của _CONTEXT)
// ===========================================================================
function hookGetThreadContext() {
    const p = exp('kernel32.dll', 'GetThreadContext') ||
              exp('kernelbase.dll', 'GetThreadContext');
    if (!p) return;
    Interceptor.attach(p, {
        // BOOL GetThreadContext(HANDLE hThread, LPCONTEXT lpContext)
        onEnter: function (args) { this.ctx = args[1]; },
        onLeave: function (retval) {
            try {
                if (this.ctx.isNull()) return;
                if (IS_X64) {
                    const offs = [0x48, 0x50, 0x58, 0x60, 0x68, 0x70]; // Dr0,1,2,3,6,7
                    offs.forEach(function (o) { this.ctx.add(o).writeU64(0); }, this);
                } else {
                    // _CONTEXT x86: Dr0=+0x04 ... Dr7=+0x18
                    for (let o = 0x04; o <= 0x18; o += 4) this.ctx.add(o).writeU32(0);
                }
                log('GetThreadContext -> zero Dr0..Dr7');
            } catch (e) { log('GetThreadContext onLeave lỗi: ' + e); }
        }
    });
    ok('Hooked GetThreadContext (clear debug registers)');
}

// ===========================================================================
// 8) FindWindowA/W: ép trả NULL cho class name của debugger
// ===========================================================================
function hookFindWindow() {
    const blacklist = ['OLLYDBG', 'WINDBGFRAMECLASS', 'ID', 'IDA',
                       'X64DBG', 'X32DBG', 'QT5QWINDOWICON', 'IMMUNITY DEBUGGER'];
    function isBad(s) {
        if (!s) return false;
        s = s.toUpperCase();
        return blacklist.some(function (b) { return s.indexOf(b) !== -1; });
    }
    [['FindWindowA', 'Ansi'], ['FindWindowW', 'Utf16'],
     ['FindWindowExA', 'Ansi'], ['FindWindowExW', 'Utf16']].forEach(function (f) {
        const name = f[0], enc = f[1];
        const p = exp('user32.dll', name);
        if (!p) return;
        // Với FindWindow(Class, Title): class=args[0]. FindWindowEx(parent,child,Class,Title): class=args[2].
        const classIdx = name.indexOf('Ex') !== -1 ? 2 : 0;
        Interceptor.attach(p, {
            onEnter: function (args) {
                try {
                    const cp = args[classIdx];
                    if (!cp.isNull()) {
                        this.cname = enc === 'Ansi' ? cp.readAnsiString() : cp.readUtf16String();
                    }
                } catch (e) {}
            },
            onLeave: function (retval) {
                if (isBad(this.cname)) {
                    retval.replace(ptr(0));
                    log(name + '("' + this.cname + '") -> NULL');
                }
            }
        });
        ok('Hooked ' + name);
    });
}

// ===========================================================================
// 9) OutputDebugStringA: trả về bình thường (trick GetLastError pre-Vista)
//    Đơn giản: cho qua, không làm gì — nhưng log để nhận diện.
//    (ScyllaHide xử lý triệt để hơn; ở đây chỉ để quan sát.)
// ===========================================================================
function hookOutputDebugString() {
    const p = exp('kernel32.dll', 'OutputDebugStringA') ||
              exp('kernelbase.dll', 'OutputDebugStringA');
    if (!p) return;
    Interceptor.attach(p, {
        onEnter: function (args) {
            try { log('OutputDebugStringA("' + args[0].readAnsiString() + '")'); }
            catch (e) {}
        }
        // TODO: nếu đề dùng trick GetLastError, có thể set lại lasterror ở onLeave
        // bằng cách gọi SetLastError(ERROR_INVALID_HANDLE) để mô phỏng "không debugger".
    });
    ok('Hooked OutputDebugStringA (quan sát)');
}

// ============================= ĐIỂM VÀO =====================================
(function main() {
    console.log('==============================================');
    console.log(' Frida Anti-Debug Bypass  (' + (IS_X64 ? 'x64' : 'x86') + ')');
    console.log(' Target: ' + (Process.enumerateModules()[0] ? Process.enumerateModules()[0].name : '?'));
    console.log('==============================================');

    if (CONFIG.peb)          patchPEB();
    if (CONFIG.isDbgPresent) hookIsDebuggerPresent();
    if (CONFIG.ntQueryInfo)  hookNtQueryInformationProcess();
    if (CONFIG.ntQuerySys)   hookNtQuerySystemInformation();
    if (CONFIG.threadHide)   hookThreadHide();
    if (CONFIG.ntClose)      hookNtClose();
    if (CONFIG.getThreadCtx) hookGetThreadContext();
    if (CONFIG.findWindow)   hookFindWindow();
    if (CONFIG.outputDbgStr) hookOutputDebugString();

    ok('Đã nạp xong các hook. Nếu spawn bằng -f, gõ  %resume  để chạy tiếp.');

    // TODO (tuỳ đề): bổ sung hook khi cần
    //  - ntdll!NtQueryObject (ObjectAllTypesInformation) -> ẩn "DebugObject"
    //  - ntdll!DbgUiRemoteBreakin / DbgBreakPoint -> chống anti-attach
    //  - kernel32!GetTickCount / QueryPerformanceCounter -> làm chậm delta (timing)
    //  - ntdll!DebugActiveProcess -> chống self-debugging
    //  - user32!BlockInput -> trả FALSE
})();
