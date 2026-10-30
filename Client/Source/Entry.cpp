#include <Windows.h>
#include <tlhelp32.h>
#include <winternl.h>
#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <mutex>
#include <string>
#include <thread>

#include "../Library/Hypervisor.h"

//CommandLineToArgvW lives in shell32.
#pragma comment(lib, "shell32.lib")

typedef enum _MEMORY_INFORMATION_CLASS
{
    MemoryBasicInformation, // MEMORY_BASIC_INFORMATION
    MemoryWorkingSetInformation, // MEMORY_WORKING_SET_INFORMATION
    MemoryMappedFilenameInformation, // UNICODE_STRING
    MemoryRegionInformation, // MEMORY_REGION_INFORMATION
    MemoryWorkingSetExInformation, // MEMORY_WORKING_SET_EX_INFORMATION
    MemorySharedCommitInformation, // MEMORY_SHARED_COMMIT_INFORMATION
    MemoryImageInformation,
    MemoryRegionInformationEx,
    MemoryPrivilegedBasicInformation,
    MemoryEnclaveImageInformation,
    MemoryBasicInformationCapped
} MEMORY_INFORMATION_CLASS;

EXTERN_C NTSYSAPI NTSTATUS NTAPI NtQueryVirtualMemory(HANDLE processHandle, void* baseAddress, MEMORY_INFORMATION_CLASS memoryInformationClass, void* memoryInformation, size_t memoryInformationLength, size_t* returnLength);

//
// NtQuerySystemInformation is declared by winternl.h, so --smoke resolves it
// by name at run time and calls it through a pointer with its real
// four-parameter signature:
//
//   NTSTATUS NtQuerySystemInformation(ULONG SystemInformationClass,
//                                     PVOID SystemInformation,
//                                     ULONG SystemInformationLength,
//                                     PULONG ReturnLength);
//
// The previous local typedef carried a phantom leading HANDLE parameter, so
// every call shifted its arguments by one register: the kernel always
// received class = 0 (SystemBasicInformation), took its buffer pointer from
// the class argument, and read the length and ReturnLength from the
// arguments that followed.  The call could never succeed, so the retry loop
// always exhausted its three attempts - exactly the B4 failure observed.
//
typedef NTSTATUS(NTAPI* NtQuerySysInfoFn)(UINT32, PVOID, ULONG, PULONG);

//
// SystemModuleInformation (class 11) returns an RTL_PROCESS_MODULES: a ULONG
// NumberOfModules, four bytes of alignment padding, then an array of
// RTL_PROCESS_MODULE_INFORMATION (0x128 bytes each).  This is NOT the old
// SYSTEM_MODULE_INFORMATION layout: the entry carries a 256-byte full path
// and a separate image base, so the previous Base/Size/Timestamp/ImageName
// struct scanned the wrong offsets entirely.
//
typedef struct _RTL_PROCESS_MODULE_INFORMATION
{
    HANDLE Section;           // 0x000
    PVOID MappedBase;         // 0x008
    PVOID ImageBase;          // 0x010
    ULONG ImageSize;          // 0x018
    ULONG Flags;              // 0x01c
    USHORT LoadOrderIndex;    // 0x020
    USHORT InitOrderIndex;    // 0x022
    USHORT LoadCount;         // 0x024
    USHORT OffsetToFileName;  // 0x026
    UCHAR FullPathName[256];  // 0x028
} RTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES
{
    ULONG NumberOfModules;
    RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES;

static_assert(sizeof(RTL_PROCESS_MODULE_INFORMATION) == 0x128, "RTL_PROCESS_MODULE_INFORMATION ABI mismatch");
static_assert(offsetof(RTL_PROCESS_MODULE_INFORMATION, ImageBase) == 0x010, "RTL_PROCESS_MODULE_INFORMATION.ImageBase ABI mismatch");
static_assert(offsetof(RTL_PROCESS_MODULE_INFORMATION, ImageSize) == 0x018, "RTL_PROCESS_MODULE_INFORMATION.ImageSize ABI mismatch");
static_assert(offsetof(RTL_PROCESS_MODULE_INFORMATION, OffsetToFileName) == 0x026, "RTL_PROCESS_MODULE_INFORMATION.OffsetToFileName ABI mismatch");
static_assert(offsetof(RTL_PROCESS_MODULE_INFORMATION, FullPathName) == 0x028, "RTL_PROCESS_MODULE_INFORMATION.FullPathName ABI mismatch");
static_assert(offsetof(RTL_PROCESS_MODULES, Modules) == 0x008, "RTL_PROCESS_MODULES.Modules ABI mismatch");

constexpr UINT32 SMOKE_SYSTEM_MODULE_INFORMATION = 11;

// One page, used for the CopyProcessMemory round-trip buffer.
constexpr SIZE_T SMOKE_PAGE_SIZE = 0x1000;

ULONG64 GetModule(UINT32 pid, const wchar_t* moduleName)
{
    HANDLE targetProcessHandle = OpenProcess(PROCESS_QUERY_INFORMATION, 0, pid);
    if (!targetProcessHandle || targetProcessHandle == INVALID_HANDLE_VALUE)
        return 0;

    ULONG64 currentAddress = 0;
    MEMORY_BASIC_INFORMATION memoryInformation;
    while (VirtualQueryEx(targetProcessHandle, reinterpret_cast<void*>(currentAddress), &memoryInformation, sizeof(memoryInformation)))
    {
        if (memoryInformation.Type == MEM_MAPPED || memoryInformation.Type == MEM_IMAGE)
        {
            constexpr size_t bufferSize = 1024;
            void* buffer = malloc(bufferSize);

            if (buffer)
            {
                size_t bytesOut = 0;
                NTSTATUS status = NtQueryVirtualMemory(targetProcessHandle, memoryInformation.BaseAddress, MemoryMappedFilenameInformation, buffer, bufferSize, &bytesOut);
                if (status == 0 && bytesOut >= sizeof(UNICODE_STRING))
                {
                    UNICODE_STRING* stringBuffer = static_cast<UNICODE_STRING*>(buffer);
                    const size_t maxChars = (bytesOut - sizeof(UNICODE_STRING)) / sizeof(wchar_t);
                    const size_t length = (std::min)(static_cast<size_t>(stringBuffer->Length) / sizeof(wchar_t), maxChars);

                    if (stringBuffer->Buffer && length != 0)
                    {
                        const std::wstring path(stringBuffer->Buffer, length);
                        if (path.find(moduleName) != std::wstring::npos &&
                            path.find(L".mui") == std::wstring::npos)
                        {
                            free(buffer);
                            CloseHandle(targetProcessHandle);
                            return reinterpret_cast<ULONG64>(memoryInformation.BaseAddress);
                        }
                    }
                }

                free(buffer);
            }
        }

        const ULONG64 nextAddress = reinterpret_cast<ULONG64>(memoryInformation.BaseAddress) + memoryInformation.RegionSize;
        if (nextAddress <= currentAddress)
            break;

        currentAddress = nextAddress;
    }

    CloseHandle(targetProcessHandle);
    return 0;
}

UINT32 LookupProcessId(const wchar_t* processName)
{
    const auto LowerWchar = [](wchar_t c) {
        if (c >= L'A' && c <= L'Z')
            return static_cast<wchar_t>(c - L'A' + L'a');
        return c;
    };

    std::wstring name = processName ? processName : L"";
    std::transform(name.begin(), name.end(), name.begin(), LowerWchar);

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot)
    {
        PROCESSENTRY32W entry = { 0 };
        entry.dwSize = sizeof(entry);
        if (Process32FirstW(snapshot, &entry))
        {
            do
            {
                std::wstring exe = entry.szExeFile;
                std::transform(exe.begin(), exe.end(), exe.begin(), LowerWchar);

                if (exe == name)
                {
                    CloseHandle(snapshot);
                    return entry.th32ProcessID;
                }
            } while (Process32NextW(snapshot, &entry));
        }

        CloseHandle(snapshot);
    }

    return 0;
}

std::mutex m;
ULONG64 MainModule = 0;
void ThreadBench(int id)
{
    char label[16];
    snprintf(label, sizeof(label), "Thread%d", id);

    thread_local uint32_t randomState = static_cast<uint32_t>(
        GetCurrentThreadId() ^ static_cast<uint32_t>(GetTickCount64()));

    while (true)
    {
        UINT64 totalOk = 0;
        UINT64 totalFail = 0;

        auto t1 = std::chrono::high_resolution_clock::now();
        for (int i = 0; i < 100000; i++)
        {
            randomState = randomState * 1664525u + 1013904223u;
            int offset = static_cast<int>(randomState % 20) + 1;
            offset += 0x48;
            volatile int readValue = Hypervisor::Read<int>(MainModule + offset);
            volatile int readConfirm = Hypervisor::Read<int>(MainModule + offset);
            if (readValue == readConfirm && readValue != 0)
                totalOk++;
            else
            {
                totalFail++;
                m.lock();
                Console::Fail(label, "invalid read 0x%x vs 0x%x", readValue, readConfirm);
                m.unlock();
            }
        }
        auto t2 = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(t2 - t1).count();
        m.lock();
        Console::Ok(label, "%llu ok | %llu failed | %lld ms", totalOk, totalFail, duration);
        m.unlock();
    }
}

//
// --smoke verification mode. Exercises the hypervisor from user mode:
//   B1 CheckPresence, B2 GetDriverInfo, B3 CopyProcessMemory round-trip,
//   B4 kernel module enumeration (Mapper/Hypervisor must be absent).
// Prints PASS/FAIL per step and returns the number of failed steps (0 = all pass).
//
int RunSmokeTest()
{
    int failures = 0;

    //
    // Lowercase a wide string (mirrors the local LowerWchar helper in
    // LookupProcessId) for case-insensitive module-name matching.
    //
    auto LowerWchar = [](wchar_t c)
    {
        if (c >= L'A' && c <= L'Z')
            return static_cast<wchar_t>(c - L'A' + L'a');
        return c;
    };

    //
    // B1 — CheckPresence: the handler returns Shared::COMM_CHECK (0xdead) in RAX.
    //
    {
        const ULONG64 out = Hypervisor::CallVM(Hypervisor::Shared::MAGIC, Hypervisor::Shared::CommandId::CheckPresence);
        if (out == Hypervisor::Shared::COMM_CHECK)
        {
            Console::Ok("CheckPresence", "0x%llx", static_cast<unsigned long long>(out));
        }
        else
        {
            Console::Fail("CheckPresence", "0x%llx (expected 0x%llx)",
                static_cast<unsigned long long>(out), static_cast<unsigned long long>(Hypervisor::Shared::COMM_CHECK));
            failures++;
        }
    }

    //
    // B2 — GetDriverInfo: validate DriverBase (kernel VA), DriverSize, TextBase, TextSize.
    //
    {
        Hypervisor::Shared::DRIVER_INFO info = { 0 };
        const ULONG64 out = Hypervisor::CallVM(Hypervisor::Shared::MAGIC, Hypervisor::Shared::CommandId::GetDriverInfo,
            reinterpret_cast<ULONG64>(&info));

        //
        // TextBase/TextSize are RVAs within the mapped driver image (the .text
        // section's VirtualAddress), NOT absolute VAs. Validate them as RVAs:
        // both must be positive and TextBase + TextSize must fit in DriverSize.
        //
        const bool valid = (out == Hypervisor::Shared::ErrorCodes::Success)
            && info.DriverBase != 0
            && info.DriverBase >= 0xFFFF800000000000ULL
            && info.DriverSize > 0
            && info.DriverSize <= 0x1000000
            && info.TextBase > 0
            && info.TextSize > 0
            && info.TextBase + info.TextSize <= info.DriverSize;

        if (valid)
        {
            Console::Ok("DriverInfo", "base 0x%llx | size %llu | text 0x%llx + %llu",
                static_cast<unsigned long long>(info.DriverBase), static_cast<unsigned long long>(info.DriverSize),
                static_cast<unsigned long long>(info.TextBase), static_cast<unsigned long long>(info.TextSize));
        }
        else
        {
            Console::Fail("DriverInfo", "status 0x%llx | base 0x%llx | size %llu | text 0x%llx + %llu",
                static_cast<unsigned long long>(out),
                static_cast<unsigned long long>(info.DriverBase), static_cast<unsigned long long>(info.DriverSize),
                static_cast<unsigned long long>(info.TextBase), static_cast<unsigned long long>(info.TextSize));
            failures++;
        }
    }

    //
    // B3 — CopyProcessMemory round-trip within the client's own process.
    //
    {
        const SIZE_T n = SMOKE_PAGE_SIZE;
        BYTE* src = static_cast<BYTE*>(malloc(n));
        BYTE* dst = static_cast<BYTE*>(malloc(n));

        if (!src || !dst)
        {
            Console::Fail("CopyProcessMemory", "allocation failed");
            failures++;
        }
        else
        {
            for (SIZE_T i = 0; i < n; i++)
                src[i] = static_cast<BYTE>((i * 251 + 37) & 0xFF);
            memset(dst, 0, n);

            const UINT32 pid = GetCurrentProcessId();
            const bool copied = Hypervisor::CopyProcessMemory(pid, reinterpret_cast<ULONG64>(src),
                pid, reinterpret_cast<ULONG64>(dst), n);

            SIZE_T firstDiff = n;
            if (copied)
            {
                for (SIZE_T i = 0; i < n; i++)
                {
                    if (src[i] != dst[i])
                    {
                        firstDiff = i;
                        break;
                    }
                }
            }

            if (copied && firstDiff == n)
            {
                Console::Ok("CopyProcessMemory", "%llu bytes matched", static_cast<unsigned long long>(n));
            }
            else
            {
                Console::Fail("CopyProcessMemory", "copied=%d | firstDiff=%llu",
                    copied, static_cast<unsigned long long>(firstDiff));
                failures++;
            }

            free(src);
            free(dst);
        }
    }

    //
    // B4 — Enumerate kernel modules; Mapper.sys and Hypervisor.sys must be absent.
    //
    {
        const NtQuerySysInfoFn ntQuerySysInfo = reinterpret_cast<NtQuerySysInfoFn>(
            GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQuerySystemInformation"));

        if (!ntQuerySysInfo)
        {
            Console::Info("ModuleEnumeration", "inconclusive (NtQuerySystemInformation unavailable)");
        }
        else
        {
            const NTSTATUS stAccessDenied = static_cast<NTSTATUS>(0xC0000022L);
            const UINT32 sysInfoClass = SMOKE_SYSTEM_MODULE_INFORMATION;

            const auto LowerAscii = [](char c)
            {
                return (c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : c;
            };

            auto interpretAndScan = [&](NTSTATUS status, void* buf, ULONG bufferSize) -> void {
                if (status == 0)
                {
                    const RTL_PROCESS_MODULES* mods = static_cast<const RTL_PROCESS_MODULES*>(buf);
                    const ULONG nMods = mods->NumberOfModules;

                    //
                    // NumberOfModules is kernel-controlled; clamp it to what
                    // the allocation can actually hold so a bogus count can
                    // never walk past the buffer.
                    //
                    const SIZE_T maxMods = (bufferSize > offsetof(RTL_PROCESS_MODULES, Modules))
                        ? (bufferSize - offsetof(RTL_PROCESS_MODULES, Modules)) / sizeof(RTL_PROCESS_MODULE_INFORMATION)
                        : 0;

                    bool found = false;
                    for (ULONG i = 0; i < nMods && i < maxMods; i++)
                    {
                        const RTL_PROCESS_MODULE_INFORMATION& m = mods->Modules[i];

                        //
                        // FullPathName is a fixed 256-byte ANSI field; bound
                        // the scan in case the kernel ever leaves it
                        // unterminated.
                        //
                        const char* fullPath = reinterpret_cast<const char*>(m.FullPathName);
                        size_t pathLength = 0;
                        while (pathLength < sizeof(m.FullPathName) && fullPath[pathLength] != '\0')
                            pathLength++;

                        std::string name(fullPath, pathLength);
                        std::transform(name.begin(), name.end(), name.begin(), LowerAscii);

                        const char* moduleLabel = nullptr;
                        if (name.find("mapper") != std::string::npos)        moduleLabel = "Mapper.sys";
                        else if (name.find("hypervisor") != std::string::npos) moduleLabel = "Hypervisor.sys";
                        else if (name.find("pdfw") != std::string::npos)     moduleLabel = "PdFwKrnl.sys";
                        else if (name.find("amerger") != std::string::npos)  moduleLabel = "Ameger module";
                        if (moduleLabel) {
                            Console::Fail("ModuleEnumeration", "found %s at 0x%llx", moduleLabel, (unsigned long long)m.ImageBase);
                            failures++;
                            found = true;
                        }
                    }
                    if (!found)
                        Console::Ok("ModuleEnumeration", "clean");
                }
                else if (status == stAccessDenied)
                    Console::Info("ModuleEnumeration", "inconclusive (query denied)");
                else {
                    Console::Fail("ModuleEnumeration", "status 0x%08X", (unsigned)status);
                    failures++;
                }
            };

            // Probe: zero-length call. Some builds populate requiredSize here,
            // some do not. Print the value so we know.
            ULONG requiredSize = 0;
            NTSTATUS stProbe = ntQuerySysInfo(sysInfoClass, nullptr, 0, &requiredSize);
            Console::Info("ModuleEnumeration", "probe status 0x%08X | required %lu",
                (unsigned)stProbe, (unsigned long)requiredSize);

            if (stProbe == stAccessDenied) {
                Console::Info("ModuleEnumeration", "inconclusive (query denied at probe)");
            }
            else {
                // Choose initial size. If probe populated requiredSize, use it;
                // otherwise fall back to a conservative estimate (512 modules).
                SIZE_T size = (requiredSize > 0)
                    ? (SIZE_T)requiredSize + SMOKE_PAGE_SIZE
                    : sizeof(RTL_PROCESS_MODULES) + 512 * sizeof(RTL_PROCESS_MODULE_INFORMATION);

                bool done = false;
                for (int attempt = 0; attempt < 3 && !done; attempt++) {
                    //
                    // The kernel interface takes a ULONG length; refuse to
                    // truncate a grown request silently.
                    //
                    if (size > 0xFFFFFFFFull) {
                        Console::Fail("ModuleEnumeration", "buffer size overflow (size=%llu)", (unsigned long long)size);
                        failures++;
                        done = true;
                        break;
                    }

                    void* buf = malloc(size);
                    if (!buf) {
                        Console::Fail("ModuleEnumeration", "allocation failed (size=%llu)", (unsigned long long)size);
                        failures++;
                        done = true;
                        break;
                    }
                    ULONG returned = 0;
                    NTSTATUS st = ntQuerySysInfo(sysInfoClass, buf, static_cast<ULONG>(size), &returned);
                    Console::Info("ModuleEnumeration", "attempt %d | size %llu | status 0x%08X",
                        attempt + 1, (unsigned long long)size, (unsigned)st);

                    if (st == 0) {
                        interpretAndScan(st, buf, static_cast<ULONG>(size));
                        free(buf);
                        done = true;
                        break;
                    }
                    if (st == stAccessDenied) {
                        Console::Info("ModuleEnumeration", "inconclusive (query denied on attempt %d)", attempt + 1);
                        free(buf);
                        done = true;
                        break;
                    }
                    // Grow the buffer for the next attempt. Prefer the kernel-
                    // reported required size if it's larger than what we used;
                    // otherwise double.
                    if (returned > size) {
                        size = (SIZE_T)returned + SMOKE_PAGE_SIZE;
                    } else {
                        size *= 2;
                    }
                    free(buf);
                }
                if (!done) {
                    Console::Fail("ModuleEnumeration", "query failed after 3 attempts");
                    failures++;
                }
            }
        }
    }

    if (failures == 0)
        Console::Ok("SmokeResult", "0 failures");
    else
        Console::Fail("SmokeResult", "%d failures", failures);

    return failures;
}

int main()
{
    Console::Init();

    //
    // Target process name comes from the command line (wide, so Unicode
    // names work), defaulting to the historical benchmark target.  This
    // lets the client be pointed at any running process, e.g.
    // "client.exe explorer.exe".
    //
    int argcW = 0;
    LPWSTR* argvW = CommandLineToArgvW(GetCommandLineW(), &argcW);
    struct ArgvGuard
    {
        LPWSTR* Value;
        ~ArgvGuard()
        {
            if (Value)
                LocalFree(Value);
        }
    } argvGuard = { argvW };
    const wchar_t* targetProcessName = (argvW && argcW > 1) ? argvW[1] : L"SystemInformer.exe";

    //
    // --smoke: run the four-step verification (B1-B4), print the result of
    // each step, and exit with the failure count (0 = all pass).  When
    // --smoke is absent, main() proceeds exactly as it did before.
    //
    auto lower = [](const std::wstring& s)
    {
        std::wstring out(s);
        std::transform(out.begin(), out.end(), out.begin(), [](wchar_t c)
        {
            return (c >= L'A' && c <= L'Z') ? static_cast<wchar_t>(c - L'A' + L'a') : c;
        });
        return out;
    };
    bool smoke = false;
    for (int i = 0; i < argcW; i++)
        if (lower(argvW[i]) == L"--smoke")
            smoke = true;
    if (smoke)
    {
        Console::Step("Session", "--smoke verification");
        return RunSmokeTest();
    }

    //
    // CallVM directly (rather than CheckPresence()) so the raw answer can be
    // reported, whether it matched or not.
    //
    const ULONG64 presence = Hypervisor::CallVM(Hypervisor::Shared::MAGIC, Hypervisor::Shared::CommandId::CheckPresence);
    if (presence != Hypervisor::Shared::COMM_CHECK)
    {
        Console::Fail("CheckPresence", "0x%llx (expected 0x%llx)",
            static_cast<unsigned long long>(presence), static_cast<unsigned long long>(Hypervisor::Shared::COMM_CHECK));
        getchar();
        return EXIT_FAILURE;
    }
    Console::Ok("CheckPresence", "0x%llx", static_cast<unsigned long long>(presence));

    if (!Hypervisor::Protect())
    {
        Console::Fail("ProtectSelf", "failed");
        getchar();
        return EXIT_FAILURE;
    }
    Console::Ok("ProtectSelf", "success");

    //
    // ProtectSelf() only sets TlbControl on each published VMCB; a vCPU that
    // was already inside VMRUN at that moment flushes at its next exit.  Pin
    // the thread to every processor in turn and issue one no-op VMMCALL so
    // each of them takes that exit now.
    //
    DWORD flushed = 0;
    DWORD processors = 0;
    const bool allFlushed = Hypervisor::FlushAllProcessors(&flushed, &processors);
    if (allFlushed)
        Console::Ok("NptFlush", "%lu/%lu processors", static_cast<unsigned long>(flushed), static_cast<unsigned long>(processors));
    else if (flushed == 0)
        Console::Fail("NptFlush", "%lu/%lu processors", static_cast<unsigned long>(flushed), static_cast<unsigned long>(processors));
    else
        Console::Info("NptFlush", "%lu/%lu processors (partial)", static_cast<unsigned long>(flushed), static_cast<unsigned long>(processors));

    //
    // Self-sufficient driver info: ask the driver to return the driver's own
    // image base/size and its resolved .text section range.
    //
    Hypervisor::Shared::DRIVER_INFO driverInfo = { 0 };
    if (Hypervisor::GetDriverInfo(driverInfo))
    {
        Console::Ok("DriverInfo", "base 0x%llx | size %llu | text 0x%llx + %llu",
            static_cast<unsigned long long>(driverInfo.DriverBase),
            static_cast<unsigned long long>(driverInfo.DriverSize),
            static_cast<unsigned long long>(driverInfo.TextBase),
            static_cast<unsigned long long>(driverInfo.TextSize));
    }
    else
    {
        Console::Fail("DriverInfo", "query failed");
    }

    const UINT32 targetProcessId = LookupProcessId(targetProcessName);
    if (!targetProcessId)
    {
        Console::Fail("TargetProcess", "not found (%ls)", targetProcessName);
        getchar();
        return EXIT_FAILURE;
    }
    Console::Ok("TargetProcess", "%ls (PID %lu)", targetProcessName, static_cast<unsigned long>(targetProcessId));

    if (!Hypervisor::AttachToProcess(targetProcessId))
    {
        Console::Fail("AttachToProcess", "failed (PID %lu)", static_cast<unsigned long>(targetProcessId));
        getchar();
        return EXIT_FAILURE;
    }

    Console::Ok("CurrentContext", "EPROCESS 0x%llx | CR3 0x%llx",
        static_cast<unsigned long long>(Hypervisor::Data::CurrentEPROCESS),
        static_cast<unsigned long long>(Hypervisor::Data::CurrentDirectoryBase));
    Console::Ok("TargetContext", "EPROCESS 0x%llx | CR3 0x%llx",
        static_cast<unsigned long long>(Hypervisor::Data::TargetEPROCESS),
        static_cast<unsigned long long>(Hypervisor::Data::TargetDirectoryBase));

    MainModule = GetModule(targetProcessId, targetProcessName);
    if (!MainModule)
    {
        Console::Fail("ModuleBase", "not found (%ls)", targetProcessName);
        getchar();
        return EXIT_FAILURE;
    }
    Console::Ok("ModuleBase", "0x%llx", static_cast<unsigned long long>(MainModule));

    const UINT64 header = Hypervisor::Read<UINT64>(MainModule);
    if (!header)
    {
        Console::Fail("ModuleHeader", "read failed");
        getchar();
        return EXIT_FAILURE;
    }
    Console::Ok("ModuleHeader", "0x%llx", static_cast<unsigned long long>(header));

    Console::Info("ReadBenchmark", "press Enter to start");
    getchar();

    Console::Info("ReadBenchmark", "running 5 threads");
    for (int i = 0; i < 5; i++)
    {
        std::thread thread(ThreadBench, i);
        thread.detach();
        Sleep(10);
    }

    getchar();
    return EXIT_SUCCESS;
}