#pragma once

/*
 * memhv
 * https://github.com/SamuelTulach | https://tulach.cc
 */

#include <intrin.h>
#include <Windows.h>
#include <cstdarg>
#include <cstddef>
#include <cstdio>
#include <iostream>
#include <stdint.h>

/*
 * Result-line console output.
 *
 * Every line has the shape
 *
 *     [ + ] CheckPresence        : 0xdead
 *
 * i.e. a bracketed marker, the PascalCase label padded to a fixed width, a
 * separator and the value.  Values are coloured by outcome (green = ok,
 * red = failure, yellow = inconclusive/info, cyan = step/section marker).
 *
 * Colour uses VT sequences and is enabled only when stdout is a real console
 * that accepted ENABLE_VIRTUAL_TERMINAL_PROCESSING.  When the output is
 * redirected, or the console refuses VT, Init() leaves colour off and the
 * helpers emit the same text without any escape bytes.
 */
#ifndef ENABLE_VIRTUAL_TERMINAL_PROCESSING
#define ENABLE_VIRTUAL_TERMINAL_PROCESSING 0x0004
#endif

namespace Console
{
    inline bool& ColorEnabled()
    {
        static bool enabled = false;
        return enabled;
    }

    inline void Init()
    {
        ColorEnabled() = false;

        const HANDLE output = GetStdHandle(STD_OUTPUT_HANDLE);
        if (!output || output == INVALID_HANDLE_VALUE)
            return;

        DWORD mode = 0;
        if (!GetConsoleMode(output, &mode))
            return; // redirected: no console, so no colour

        if (!SetConsoleMode(output, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING))
            return; // console rejected VT: stay plain

        ColorEnabled() = true;
    }

    enum class Tone
    {
        Ok,
        Fail,
        Info,
        Step,
    };

    inline const char* Marker(Tone tone)
    {
        switch (tone)
        {
        case Tone::Ok:   return "+";
        case Tone::Fail: return "!";
        case Tone::Info: return "*";
        default:         return ">";
        }
    }

    inline const char* Color(Tone tone)
    {
        switch (tone)
        {
        case Tone::Ok:   return "\x1b[92m"; // bright green
        case Tone::Fail: return "\x1b[91m"; // bright red
        case Tone::Info: return "\x1b[93m"; // bright yellow
        default:         return "\x1b[96m"; // bright cyan
        }
    }

    inline void Emit(Tone tone, const char* label, const char* format, va_list args)
    {
        char value[512];
        vsnprintf(value, sizeof(value), format, args);

        if (!ColorEnabled())
        {
            printf("[ %s ] %-24s : %s\n", Marker(tone), label, value);
            return;
        }

        const char* color = Color(tone);
        printf("%s[ %s ]\x1b[0m %-24s : %s%s\x1b[0m\n", color, Marker(tone), label, color, value);
    }

    inline void Ok(const char* label, const char* format, ...)
    {
        va_list args;
        va_start(args, format);
        Emit(Tone::Ok, label, format, args);
        va_end(args);
    }

    inline void Fail(const char* label, const char* format, ...)
    {
        va_list args;
        va_start(args, format);
        Emit(Tone::Fail, label, format, args);
        va_end(args);
    }

    inline void Info(const char* label, const char* format, ...)
    {
        va_list args;
        va_start(args, format);
        Emit(Tone::Info, label, format, args);
        va_end(args);
    }

    inline void Step(const char* label, const char* format, ...)
    {
        va_list args;
        va_start(args, format);
        Emit(Tone::Step, label, format, args);
        va_end(args);
    }
}

namespace Hypervisor
{
    namespace Shared
    {
        constexpr ULONG64 MAGIC = 0xfeed3;
        constexpr ULONG64 COMM_CHECK = 0xdead;

        constexpr ULONG64 MAX_RW_SIZE = 0x10000;

        enum CommandId
        {
            Invalid,
            CheckPresence,
            GetProcess,
            GetDirectoryBase,
            CopyProcessMemory,
            ProtectSelf,
            FlushNpt,
            ProtectRange,
            GetDriverInfo,
        };

        enum ErrorCodes
        {
            Success,
            ControlBlockReadFail,
            MemoryCopyTooLarge,
            MemoryCopyFailSource,
            MemoryCopyFailTarget,
            InvalidProcess,
        };

        /*
         * Must stay byte-for-byte identical to Hypervisor/Source/Common/Shared.h.
         * The driver resolves both ends of a copy by PID; directory bases never
         * cross the VMMCALL boundary.
         */
        typedef struct _COPY_MEMORY_DATA
        {
            ULONG32 SourceProcessId;        // 0x00
            ULONG32 DestinationProcessId;   // 0x04
            ULONG64 SourceAddress;          // 0x08
            ULONG64 DestinationAddress;     // 0x10
            SIZE_T NumberOfBytes;           // 0x18
        } COPY_MEMORY_DATA;

        static_assert(sizeof(COPY_MEMORY_DATA) == 32, "COPY_MEMORY_DATA ABI mismatch");
        static_assert(offsetof(COPY_MEMORY_DATA, SourceProcessId) == 0x00, "COPY_MEMORY_DATA.SourceProcessId ABI mismatch");
        static_assert(offsetof(COPY_MEMORY_DATA, DestinationProcessId) == 0x04, "COPY_MEMORY_DATA.DestinationProcessId ABI mismatch");
        static_assert(offsetof(COPY_MEMORY_DATA, SourceAddress) == 0x08, "COPY_MEMORY_DATA.SourceAddress ABI mismatch");
        static_assert(offsetof(COPY_MEMORY_DATA, DestinationAddress) == 0x10, "COPY_MEMORY_DATA.DestinationAddress ABI mismatch");
        static_assert(offsetof(COPY_MEMORY_DATA, NumberOfBytes) == 0x18, "COPY_MEMORY_DATA.NumberOfBytes ABI mismatch");

        //
        // GetDriverInfo (command 0x08): returns the driver's image base/size and its
        // resolved .text section range.  Written to the caller's user buffer (R8).
        //
        typedef struct _DRIVER_INFO
        {
            ULONG64 DriverBase;    // 0x00
            SIZE_T  DriverSize;    // 0x08
            ULONG64 TextBase;      // 0x10
            SIZE_T  TextSize;      // 0x18
        } DRIVER_INFO;

        static_assert(sizeof(DRIVER_INFO) == 32, "DRIVER_INFO ABI mismatch");
        static_assert(offsetof(DRIVER_INFO, DriverBase) == 0x00, "DRIVER_INFO.DriverBase ABI mismatch");
        static_assert(offsetof(DRIVER_INFO, DriverSize) == 0x08, "DRIVER_INFO.DriverSize ABI mismatch");
        static_assert(offsetof(DRIVER_INFO, TextBase) == 0x10, "DRIVER_INFO.TextBase ABI mismatch");
        static_assert(offsetof(DRIVER_INFO, TextSize) == 0x18, "DRIVER_INFO.TextSize ABI mismatch");
    }

    namespace Data
    {
        inline bool Attached = false; // dont be too attached to females, they bite
        inline PVOID Shellcode = nullptr;

        //
        // PIDs are the only process identity that crosses the VMMCALL
        // boundary; the driver looks each one up with PsLookupProcessByProcessId.
        //
        inline ULONG32 CurrentProcessId = 0;
        inline ULONG32 TargetProcessId = 0;

        inline ULONG64 CurrentEPROCESS = 0;
        inline ULONG64 CurrentDirectoryBase = 0;

        inline HANDLE TargetProcessHandle = nullptr;
        inline ULONG64 TargetEPROCESS = 0;
        inline ULONG64 TargetDirectoryBase = 0;
    }

    inline ULONG64 CallVM(ULONG64 arg1 = 0, ULONG64 arg2 = 0, ULONG64 arg3 = 0, ULONG64 arg4 = 0)
    {
        if (!Data::Shellcode)
        {
            // vmmcall
            // ret
            const BYTE code[] = { 0x0F, 0x01, 0xD9, 0xC3 };

            Data::Shellcode = VirtualAlloc(nullptr, sizeof(code), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (!Data::Shellcode)
                throw std::exception("Out of memory");

            memcpy(Data::Shellcode, code, sizeof(code));
        }

        typedef ULONG64(__stdcall* CallFunc)(ULONG64 arg1, ULONG64 arg2, ULONG64 arg3, ULONG64 arg4);
        const CallFunc func = reinterpret_cast<CallFunc>(Data::Shellcode);

        ULONG64 output;
        __try
        {
            output = func(arg1, arg2, arg3, arg4);
        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            Console::Fail("VmmCall", "SEH exception (no hypervisor?)");
            output = 0xAABB;
        }

        return output;
    }

    inline bool Error(ULONG64 hvOutput)
    {
        if (hvOutput == 0xAABB)
            return true; // HV not loaded

        if (hvOutput == 0xFFFF)
            return true; // command not implemented

        if (!hvOutput)
            return true; // empty output

        return false;
    }

    //
    // Blanks an arbitrary guest virtual range [base, base + size) in the NPT,
    // redirecting each page to the shared blank page - the same primitive
    // ProtectSelf() uses on the hypervisor's own image.  Pass the kernel
    // virtual base the mapper allocated (its DriverObject DriverStart) and
    // the allocation size (DriverSize).  Call it after every driver you want
    // hidden has run DriverEntry, and run FlushAllProcessors() once afterwards.
    //
    inline bool HideMemory(ULONG64 base, SIZE_T size)
    {
        const ULONG64 output = CallVM(Shared::MAGIC, Shared::CommandId::ProtectRange, base, static_cast<ULONG64>(size));
        return output == Shared::ErrorCodes::Success;
    }

    inline bool CheckPresence()
    {
        const ULONG64 output = CallVM(Shared::MAGIC, Shared::CommandId::CheckPresence);
        return output == Shared::COMM_CHECK;
    }

    inline bool Protect()
    {
        const ULONG64 output = CallVM(Shared::MAGIC, Shared::CommandId::ProtectSelf);
        return output == Shared::ErrorCodes::Success;
    }

    //
    // Asks the driver to return the driver's own image base/size and its
    // resolved .text range into the caller's `info` buffer.  The driver writes
    // the DRIVER_INFO struct to the R8 pointer and returns Success (0).
    //
    inline bool GetDriverInfo(Shared::DRIVER_INFO& info)
    {
        const ULONG64 output = CallVM(Shared::MAGIC, Shared::CommandId::GetDriverInfo,
            reinterpret_cast<ULONG64>(&info));
        return output == Shared::ErrorCodes::Success;
    }

    /*
     * Forces every active processor through one #VMEXIT.
     *
     * ProtectSelf() bumps the shared NPT flush generation and sets TlbControl
     * on every published VMCB, but a vCPU that is already inside VMRUN when
     * that store lands never sees it and would only flush at its next exit.
     * Issuing FlushNpt from each CPU pins the current thread to that CPU, so
     * the VMMCALL itself is the exit that arms the flush.
     *
     * Single-threaded on purpose: the shellcode in Data::Shellcode is global
     * state, and a pinned sweep covers every CPU without racing on it.
     *
     * Prints nothing: the caller reports one summary line from the counts
     * returned through `succeeded`/`total` (both optional).
     */
    inline bool FlushAllProcessors(DWORD* succeeded = nullptr, DWORD* total = nullptr)
    {
        if (succeeded)
            *succeeded = 0;
        if (total)
            *total = 0;

        const DWORD processorCount = GetActiveProcessorCount(ALL_PROCESSOR_GROUPS);
        if (processorCount == 0)
            return false;

        if (total)
            *total = processorCount;

        const HANDLE thread = GetCurrentThread();

        GROUP_AFFINITY original = { 0 };
        if (!GetThreadGroupAffinity(thread, &original))
            return false;

        bool allFlushed = true;
        DWORD flushed = 0;
        for (DWORD index = 0; index < processorCount; index++)
        {
            GROUP_AFFINITY affinity = { 0 };
            affinity.Group = static_cast<WORD>(index / 64);
            affinity.Mask = 1ULL << (index % 64);

            GROUP_AFFINITY previous = { 0 };
            if (!SetThreadGroupAffinity(thread, &affinity, &previous))
            {
                allFlushed = false;
                continue;
            }

            if (CallVM(Shared::MAGIC, Shared::CommandId::FlushNpt) != Shared::ErrorCodes::Success)
                allFlushed = false;
            else
                flushed++;
        }

        SetThreadGroupAffinity(thread, &original, nullptr);

        if (succeeded)
            *succeeded = flushed;

        return allFlushed;
    }

    inline ULONG64 GetEPROCESS(UINT32 processId)
    {
        return CallVM(Shared::MAGIC, Shared::CommandId::GetProcess, processId);
    }

    //
    // The driver resolves the directory base from a PID
    // (PsLookupProcessByProcessId -> EPROCESS->DirectoryTableBase); it cannot
    // accept an EPROCESS pointer, whose kernel address would be truncated to
    // a ULONG32 and misread as a PID.
    //
    inline ULONG64 GetDirbase(ULONG32 processId)
    {
        return CallVM(Shared::MAGIC, Shared::CommandId::GetDirectoryBase, processId);
    }

    inline bool AttachToProcess(UINT32 processId)
    {
        Data::CurrentProcessId = GetCurrentProcessId();
        Data::TargetProcessId = processId;

        Data::CurrentEPROCESS = GetEPROCESS(Data::CurrentProcessId);
        if (Error(Data::CurrentEPROCESS))
            return false;

        Data::TargetEPROCESS = GetEPROCESS(Data::TargetProcessId);
        if (Error(Data::TargetEPROCESS))
            return false;

        //
        // GetDirbase() returns 0 on failure (the driver no longer reports the
        // InvalidProcess code, which Error() could not distinguish from a
        // legitimate CR3), so a zero result is rejected explicitly here.
        //
        Data::CurrentDirectoryBase = GetDirbase(Data::CurrentProcessId);
        if (Data::CurrentDirectoryBase == 0)
            return false;

        Data::TargetDirectoryBase = GetDirbase(Data::TargetProcessId);
        if (Data::TargetDirectoryBase == 0)
            return false;

        Data::TargetProcessHandle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, processId);
        if (!Data::TargetProcessHandle || Data::TargetProcessHandle == INVALID_HANDLE_VALUE)
            return false;

        Data::Attached = true;
        return true;
    }

    inline bool CopyProcessMemory(ULONG32 sourceProcessId, ULONG64 sourceAddress, ULONG32 targetProcessId, ULONG64 targetAddress, SIZE_T bytes)
    {
        //
        // The protocol caps one VMMCALL at Shared::MAX_RW_SIZE (the kernel
        // stages the transfer in a fixed buffer), so larger requests are
        // split here into consecutive calls.  Every chunk is validated
        // end-to-end by the driver like a standalone copy, so a chunk that
        // fails aborts the remainder and reports failure for the request.
        //
        ULONG64 source = sourceAddress;
        ULONG64 target = targetAddress;
        SIZE_T remaining = bytes;

        while (remaining)
        {
            const ULONG64 chunk = (remaining > Shared::MAX_RW_SIZE) ? static_cast<ULONG64>(Shared::MAX_RW_SIZE) : remaining;

            Shared::COPY_MEMORY_DATA data = { 0 };
            data.SourceProcessId = sourceProcessId;
            data.DestinationProcessId = targetProcessId;
            data.SourceAddress = source;
            data.DestinationAddress = target;
            data.NumberOfBytes = chunk;

            const ULONG64 value = CallVM(Shared::MAGIC, Shared::CommandId::CopyProcessMemory, reinterpret_cast<ULONG64>(&data));
            if (value != Shared::ErrorCodes::Success)
                return false;

            source += chunk;
            target += chunk;
            remaining -= static_cast<SIZE_T>(chunk);
        }

        return true;
    }

    inline bool ReadMemory(ULONG64 source, ULONG64 buffer, SIZE_T size)
    {
        memset(reinterpret_cast<PVOID>(buffer), 0, size);
        return CopyProcessMemory(Data::TargetProcessId, source, Data::CurrentProcessId, buffer, size);
    }

    /*
     * The copy path resolves through physical page tables, so both the
     * source and the destination of every read/write must be RESIDENT
     * (present PTEs at every level).  A non-resident page (paged out, or
     * committed but never touched - demand zero) makes the whole request
     * fail; nothing is silently skipped, so a caller that receives true can
     * trust every byte.  Live memory of a running process is always
     * resident; a freshly allocated, never-touched remote buffer is not, so
     * touch it before writing to it.
     */
    inline bool WriteMemory(ULONG64 buffer, ULONG64 destination, SIZE_T size)
    {
        return CopyProcessMemory(Data::CurrentProcessId, buffer, Data::TargetProcessId, destination, size);
    }

    template<typename T>
    T Read(ULONG64 address)
    {
        T value = T();
        ReadMemory(address, (ULONG64)&value, sizeof(T));
        return value;
    }

    template<typename T>
    void Write(ULONG64 address, T value)
    {
        WriteMemory((ULONG64)&value, address, sizeof(T));
    }
}
