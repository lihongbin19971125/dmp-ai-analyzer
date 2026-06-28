//! Shared test fixtures for dmp-core integration tests.
//! Replicates sample CDB output from Python MVP tests.

#![allow(dead_code)]

/// Full CDB output from a typical access violation crash.
pub const SAMPLE_FULL_CDB_OUTPUT: &str = r"Debug session time: Mon Jun 23 15:26:44.000 2026 (UTC + 8:00)

Windows 10 Version 26200 MP (12 procs) Free x64
Product: WinNt
Machine Name: DESKTOP-CRASH01
OS_VERSION: 10.0.26200.1

OSNAME: Windows 10 Pro
OSPLATFORM_TYPE: x64

ExceptionCode: C0000005 (Access violation)
ExceptionAddress: 00007ff6`12345678
Attempt to read from address 00000000`00000000
First chance exception

STACK_TEXT:
00000032`5717c530 00007ff6`12345678 myapp!CrashFunc+0x10 [d:\src\crash.cpp @ 42]
00000032`5717c538 00007ff6`12346780 myapp!WorkerThread+0x88 [d:\src\worker.cpp @ 156]

CONTEXT:  (.ecxr)
rax=0000000000000000 rbx=000000325717cab0 rcx=000000325717c530
rdx=000000325717c9e0 rsi=000000325717cab0 rdi=000000325717c530
rip=00007ff612345678 rsp=000000325717c530 rbp=000000325717c9e0
efl=00010246

start    end        module name
00007ff6`12340000 00007ff6`12380000 myapp
    Image path: C:\Program Files\MyApp\myapp.exe
00007ff8`00000000 00007ff8`00120000 ntdll
    Image path: C:\Windows\System32\ntdll.dll
";

/// Pass2 output (heap, locks, address summary).
pub const SAMPLE_PASS2_OUTPUT: &str = r"
start    end        module name
00007ff6`12340000 00007ff6`12380000 myapp
    Image path: C:\Program Files\MyApp\myapp.exe
00007ff8`00000000 00007ff8`00120000 ntdll
    Image path: C:\Windows\System32\ntdll.dll

5 heaps found
LFH Key: 0x7ffe12345678
Termination on corruption: ENABLED

  Heap 0000012340000000
    Reserved 0000000002000000 (32768 KB)
    Committed 0000000001500000 (21504 KB)
    Free 0000000000080000 (512 KB)
    Virtual address space: 8 segments
    Lock contention: 42

  Heap 0000012340010000
    Reserved 0000000001000000 (16384 KB)
    Committed 0000000000800000 (8192 KB)
    Free 0000000000040000 (256 KB)
    Virtual address space: 3 segments

  Heap 0000012340020000
    Reserved 0000000000080000 (512 KB)
    Committed 0000000000040000 (256 KB)
    Free 0000000000010000 (64 KB)
    Virtual address space: 2 segments

CritSec ntdll!LdrpLoaderLock+0 at 00007fff`12345678
CritSec myapp!g_ConfigLock+0 at 00007ff6`12346780

--- Usage Summary ---------------- RgnCount ----------- Total Size -------- %ofBusy %ofTotal
Free                                     45          7ffe`00000000 ( 127.992 TB)           65.00%
Image                                   342            7`3f4b0000 (   1.813 GB)  25.00%    8.75%
Heap                                     55            2`8a3b0000 ( 650.000 MB)   8.90%    3.11%
Stack                                    12              8c000000 (   2.188 GB)  30.00%   10.50%
MappedFile                               28              50000000 (  80.000 MB)   1.10%    0.38%
Other                                     8              15000000 (  21.000 MB)   0.29%    0.10%
TEB                                       6               600000 (   6.000 MB)   0.08%    0.03%
PEB                                       1                 1000 (   4.000 KB)   0.00%    0.00%

--- State Summary ---------------- RgnCount ----------- Total Size -------- %ofBusy %ofTotal
MEM_FREE                                45          7ffe`00000000 ( 127.992 TB)           65.00%
MEM_RESERVE                             52            1`2a3b0000 (   4.660 GB)  64.00%   22.47%
MEM_COMMIT                             402            3`8c1b0000 (  14.190 GB) 194.00%   68.84%

--- Largest Free Block by Region -
Largest free block: 7ffd`f0000000 ( 127.980 TB)
";

/// Heap info with high commit (potential leak).
pub const SAMPLE_HEAP_HIGH_COMMIT: &str = r"1 heaps found
LFH Key: 0x7ffe12345678
Termination on corruption: DISABLED

  Heap 0000012340000000
    Reserved 0000000010000000 (262144 KB)
    Committed 0000000010000000 (262144 KB)
    Free 0000000000000000 (0 KB)
    Virtual address space: 16 segments
    Lock contention: 120
";

/// Empty heap output.
pub const SAMPLE_HEAP_EMPTY: &str = r"0 heaps found
LFH Key: 0x0
Termination on corruption: DISABLED
";

/// Access violation exception.
pub const SAMPLE_EXCEPTION_AV: &str = r"
ExceptionCode: C0000005 (Access violation)
ExceptionAddress: 00007ff6`12345678
Attempt to read from address 00000000`00000000
First chance exception
";

/// Stack overflow exception.
pub const SAMPLE_EXCEPTION_SO: &str = r"
ExceptionCode: C00000FD (Stack overflow)
ExceptionAddress: 00007ff6`abcd0000
Second chance, this exception will not be handled further
";

/// CLR exception.
pub const SAMPLE_EXCEPTION_CLR: &str = r"
ExceptionCode: E0434F4D (CLR exception)
ExceptionAddress: 00007ff8`00012345
";

/// Divide by zero exception.
pub const SAMPLE_EXCEPTION_DBZ: &str = r"
ExceptionCode: C0000094 (Integer divide by zero)
ExceptionAddress: 00007ff6`99990000
";

/// Unknown exception code.
pub const SAMPLE_EXCEPTION_UNKNOWN: &str = r"
ExceptionCode: E06D7363 (C++ EH exception)
ExceptionAddress: 00007ff8`55550000
";

/// System info (vertarget).
pub const SAMPLE_SYSTEM_INFO: &str = r"Windows 10 Version 26200 MP (12 procs) Free x64
Product: WinNt, suite: SingleUserTS
Edition build lab: 26200.1.amd64fre.ge_release.250515-1710
Machine Name: DESKTOP-CRASH01

OSNAME: Windows 10 Pro
OS_VERSION: 10.0.26200.1
OSPLATFORM_TYPE: x64

System Uptime: 3 days 7:22:15

Processor: Intel(R) Core(TM) i7-13700K
4 processors

PageFile: 0x0000000200000000 ( 8192 Mb )
Physical: 0x0000000040000000 ( 16384 Mb )
Avail: 0x0000000010000000 ( 4096 Mb )

WorkingSet: 0x0000000008000000 ( 2048 Mb )

COMPUTERNAME=DESKTOP-CRASH01
USERNAME=admin123
TEMP=C:\Users\admin123\AppData\Local\Temp
";

/// All threads output.
pub const SAMPLE_THREADS: &str = r"   0  Id: 1a8c.1a90 Crashed <Memory Access Violation>
   1  Id: 1a8c.2b40 Running <Normal>
   2  Id: 1a8c.1c50 Sleep <Normal>
   3  Id: 1a8c.3d60 Sleep <Normal>
";

/// Context registers (x64).
pub const SAMPLE_REGISTERS: &str = r"rax=0000000000000000 rbx=000000325717cab0 rcx=000000325717c530
rdx=000000325717c9e0 rsi=000000325717cab0 rdi=000000325717c530
rip=00007ff612345678 rsp=000000325717c530 rbp=000000325717c9e0
efl=00010246 cs=0033 ss=002b ds=002b es=002b fs=0053 gs=002b
";

/// AI analysis sample output.
pub const SAMPLE_AI_ANALYSIS: &str = r##"## 崩溃根本原因分析

### 异常概述
异常代码 **C0000005 (ACCESS_VIOLATION)** 表明程序尝试访问无效的内存地址 `0x00000000`。

### 直接原因
在 `myapp!CrashFunc+0x10` 中，代码尝试解引用一个空指针。

### 修复建议
1. 在 `CrashFunc` 中添加空指针检查
2. 启用 ASan (Address Sanitizer) 进行内存错误检测

### 预防措施
- 添加单元测试覆盖空指针路径
- 启用静态分析工具 (PREfast)"##;

/// Second report for diff testing.
pub const SAMPLE_AI_ANALYSIS_2: &str = r##"## 崩溃根本原因分析

### 异常概述
异常代码 **C00000FD (STACK_OVERFLOW)** 表明发生了栈溢出。

### 直接原因
递归调用导致栈空间耗尽。

### 修复建议
1. 检查递归终止条件
2. 考虑使用迭代替代递归
"##;
