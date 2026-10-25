#include <Windows.h>
#include <tlhelp32.h>
#include <winternl.h>
#include <algorithm>
#include <chrono>
#include <cstdint>
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
    UNREFERENCED_PARAMETER(id);

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
                printf("[!] Invalid read: %x %x\n", readValue, readConfirm);
                m.unlock();
            }
        }
        auto t2 = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(t2 - t1).count();
        m.lock();
        printf("[+] Ok: %llu Fail: %llu In: %lld\n", totalOk, totalFail, duration);
        m.unlock();
    }
}

int main()
{
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

    printf("[>] Checking presence...\n");
    bool status = Hypervisor::CheckPresence();
    if (!status)
    {
        printf("[!] Hypervisor not running\n");
        getchar();
        return EXIT_FAILURE;
    }

    printf("[>] Instructing hypervisor to protect itself...\n");
    status = Hypervisor::Protect();
    if (!status)
    {
        printf("[!] Hypervisor self-protection failed\n");
        getchar();
        return EXIT_FAILURE;
    }

    //
    // ProtectSelf() only sets TlbControl on each published VMCB; a vCPU that
    // was already inside VMRUN at that moment flushes at its next exit.  Pin
    // the thread to every processor in turn and issue one no-op VMMCALL so
    // each of them takes that exit now.
    //
    printf("[>] Flushing NPT on all processors...\n");
    if (!Hypervisor::FlushAllProcessors())
        printf("[!] Not every processor confirmed the NPT flush\n");

    printf("[>] Searching for target process (%ls)...\n", targetProcessName);
    UINT32 targetProcessId = LookupProcessId(targetProcessName);
    if (!targetProcessId)
    {
        printf("[!] Process not found\n");
        getchar();
        return EXIT_FAILURE;
    }

    printf("[+] Process has PID of %u\n", targetProcessId);

    printf("[>] Attaching to process...\n");
    status = Hypervisor::AttachToProcess(targetProcessId);
    if (!status)
    {
        printf("[!] Failed to attach\n");
        getchar();
        return EXIT_FAILURE;
    }

    printf("[+] Current process: EPROCESS -> 0x%llx CR3 -> 0x%llx\n", Hypervisor::Data::CurrentEPROCESS, Hypervisor::Data::CurrentDirectoryBase);
    printf("[+] Target process: EPROCESS -> 0x%llx CR3 -> 0x%llx\n", Hypervisor::Data::TargetEPROCESS, Hypervisor::Data::TargetDirectoryBase);

    printf("[>] Getting module base address...\n");
    MainModule = GetModule(targetProcessId, targetProcessName);
    if (!MainModule)
    {
        printf("[!] Failed to get module base address\n");
        getchar();
        return EXIT_FAILURE;
    }

    printf("[+] Module is at 0x%llx\n", MainModule);

    printf("[>] Reading module header...\n");
    UINT64 header = Hypervisor::Read<UINT64>(MainModule);
    if (!header)
    {
        printf("[!] Failed to read header\n");
        getchar();
        return EXIT_FAILURE;
    }

    printf("[+] Header data: 0x%p\n", reinterpret_cast<void*>(header));

    printf("[>] Press any key to start multi-threaded test...\n");
    getchar();

    printf("[>] Multi-thread test...\n");
    for (int i = 0; i < 5; i++)
    {
        printf("[+] Starting ID %i...\n", i);
        std::thread thread(ThreadBench, i);
        thread.detach();
        Sleep(10);
    }

    getchar();
    return EXIT_SUCCESS;
}