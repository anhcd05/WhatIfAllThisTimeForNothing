/*
 * fake_ptrace.c  --  Thu vien LD_PRELOAD de VO HIEU HOA anti-debug dua tren ptrace
 * ---------------------------------------------------------------------------
 * MUC DICH: phuc vu phan tich / giai de CTF (Cyber SEA Game 2026).
 *
 * Y TUONG:
 *   Rat nhieu chall Linux chong debug bang cach goi:
 *       ptrace(PTRACE_TRACEME, 0, 0, 0);
 *   - Neu chua co debugger: call tra ve 0  -> chuong trinh chay binh thuong.
 *   - Neu da bi gdb/strace attach: call tra ve -1 (errno = EPERM)
 *     -> chall biet minh dang bi debug va thoat / di sai nhanh.
 *   Mot bien the khac: goi TRACEME lan 1 (thanh cong) roi goi lan 2; neu lan 2
 *   that bai (-1) thi khong sao, nhung neu lan 2 THANH CONG nghia la khong ai
 *   trace minh ca... Du bien the nao, ta deu muon ptrace() "noi doi".
 *
 *   Vi `ptrace` la ham cua glibc (wrapper quanh syscall), ta co the dung
 *   LD_PRELOAD de NAP DE thu vien nay TRUOC libc. Loader se lien ket symbol
 *   `ptrace` toi ham ben duoi thay vi cua libc => moi loi goi ptrace() tu
 *   chuong trinh deu di vao ham gia cua ta va luon tra ve gia tri "an toan".
 *
 * GIOI HAN (doc ky!):
 *   - CHI an voi binary goi ptrace QUA libc (dynamically linked, co PLT entry).
 *   - KHONG an neu chall goi syscall truc tiep (inline asm `syscall`, hoac
 *     dung syscall(SYS_ptrace, ...) ... thuc ra syscall() cung bi override duoc,
 *     xem ben duoi) hoac neu binary la static (khong dung ld.so).
 *   - Voi static binary / direct syscall: dung gdb `catch syscall ptrace` hoac
 *     patch tinh (xem GUIDE_antidebug_linux.md).
 *
 * BIEN DICH:
 *     gcc -shared -fPIC fake_ptrace.c -o fake_ptrace.so -ldl
 *
 * CACH CHAY:
 *     LD_PRELOAD=./fake_ptrace.so ./chall
 *   Chay cung gdb:
 *     gdb -ex 'set environment LD_PRELOAD=./fake_ptrace.so' ./chall
 *   Hoac trong gdb:
 *     (gdb) set environment LD_PRELOAD ./fake_ptrace.so
 *     (gdb) run
 *
 * MUC "DO DAC": dat bien moi truong FAKE_PTRACE_VERBOSE=1 de in ra moi loi goi
 * ptrace bi chan (giup xac nhan chall co that su goi ptrace khong).
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

/*
 * Prototype cua ptrace trong glibc la:
 *     long ptrace(int request, pid_t pid, void *addr, void *data);
 * Ta khai bao lai cho khop (variadic that ra, nhung chu ky nay du dung).
 */

static int verbose(void)
{
    const char *v = getenv("FAKE_PTRACE_VERBOSE");
    return (v && v[0] == '1');
}

/*
 * Ham ptrace() GIA.
 * - Voi PTRACE_TRACEME (request == 0): tra ve 0 (gia vo "da trace thanh cong"),
 *   nhung thuc chat KHONG trace gi ca => khong khoa duoc gdb that su attach.
 * - Voi cac request khac: cung tra ve 0 cho an toan (chall hiem khi dung
 *   ptrace vao viec khac ngoai anti-debug). Neu can hanh vi khac, chinh o day.
 *
 * Luu y: ta KHONG goi ptrace that cua libc (khong dlsym RTLD_NEXT), vi neu goi
 * that thi PTRACE_TRACEME se that su self-attach va co the hong luong debug.
 * Ta chu dich "nuot" moi loi goi.
 */
long ptrace(int request, pid_t pid, void *addr, void *data)
{
    if (verbose())
        fprintf(stderr,
                "[fake_ptrace] chan ptrace(request=%d, pid=%d) -> tra ve 0\n",
                request, (int)pid);
    (void)addr;
    (void)data;
    return 0;   /* luon "thanh cong", khong bao gio -1 */
}

/*
 * Mot so chall goi ptrace gian tiep qua syscall():
 *     syscall(SYS_ptrace, PTRACE_TRACEME, 0, 0, 0);
 * De chan truong hop nay, ta override luon syscall(). Voi SYS_ptrace (101 tren
 * x86-64) ta tra ve 0; con lai thi chuyen tiep sang syscall that cua libc.
 *
 * Neu KHONG muon dung canh nay (de tranh lam hong cac syscall khac), co the
 * xoa toan bo khoi ham syscall() ben duoi -- khi do chi override ptrace().
 */
#include <dlfcn.h>
#include <stdarg.h>
#include <sys/syscall.h>
#include <unistd.h>

long syscall(long number, ...)
{
    /* Lay 6 doi so kha di cua syscall (ABI Linux toi da 6 arg). */
    va_list ap;
    long a1, a2, a3, a4, a5, a6;
    va_start(ap, number);
    a1 = va_arg(ap, long);
    a2 = va_arg(ap, long);
    a3 = va_arg(ap, long);
    a4 = va_arg(ap, long);
    a5 = va_arg(ap, long);
    a6 = va_arg(ap, long);
    va_end(ap);

    if (number == SYS_ptrace) {
        if (verbose())
            fprintf(stderr,
                    "[fake_ptrace] chan syscall(SYS_ptrace, req=%ld) -> tra ve 0\n",
                    a1);
        return 0;
    }

    /* Chuyen tiep cac syscall khac toi libc that de khong lam hong chuong trinh. */
    static long (*real_syscall)(long, ...) = NULL;
    if (!real_syscall)
        real_syscall = (long (*)(long, ...))dlsym(RTLD_NEXT, "syscall");
    if (!real_syscall) {
        /* Khong tim thay -> fallback: bao loi an toan. */
        return -1;
    }
    return real_syscall(number, a1, a2, a3, a4, a5, a6);
}
