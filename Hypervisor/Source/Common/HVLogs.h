#pragma once

//
// Diagnostic progress logger.
//
// Log()/LogNum() append a plain-text marker into the non-paged ring buffer
// below.  The ring lives only in memory: it is invisible to the guest, and
// if the machine bugchecks the ring lands in the crash dump, where the last
// markers show exactly which step failed.
//
// HARD RULE - why the ring buffer exists:
//
//   #VMEXIT/#VMMCALL handlers run with GIF=0 (the CLGI right after VMRUN in
//   SVMX64.asm), on the per-CPU host stack inside VIRTUAL_PROCESSOR_DATA,
//   and at whatever IRQL the interrupted guest context had (IRQL is software
//   state in the PCR; the hypervisor never changes it, so an exit taken in a
//   guest DPC or ISR arrives at DISPATCH_LEVEL or higher).
//
//   In that state no call may wait, allocate paged memory, or touch the file
//   system.  A wait parks the CPU with interrupts hard-disabled: the wake-up
//   is an interrupt, and with GIF=0 no interrupt - not even NMI - can ever
//   be delivered, so the CPU halts for good once it idles.  Zw* is also
//   flatly illegal above PASSIVE_LEVEL, and blocking on the host stack
//   corrupts the parked thread and the LaunchVM loop on top.
//
// Therefore Log()/LogNum() only append into the non-paged ring buffer: one
// interlocked increment plus plain stores into static memory, safe at any
// IRQL and any GIF state, from all CPUs at once.
//
// PRODUCTION STEALTH - file logging is compiled out (HYPERVISOR_LOG_ENABLE_FILE 0):
//
//   Writing C:\amager_hv.log leaves a persistent forensic trace on disk
//   naming this driver, and the flusher thread is an extra unexplained
//   System thread.  With the flag at 0 neither exists and the binary
//   contains no log path or build-stamp strings; the ring remains the
//   crash-dump diagnostic.  Flip the flag to 1 only for a debugging build.
//
#define HYPERVISOR_LOG_ENABLE_FILE 0

namespace Hypervisor
{
    inline constexpr ULONG RingCapacity = 256;   // slots, power of two
    inline constexpr ULONG RingLineBytes = 128;  // bytes per slot
    inline constexpr ULONG RingTextBytes = RingLineBytes - sizeof(LONG);

    typedef struct _LOG_SLOT
    {
        volatile LONG Length;                    // 0 = empty or being written
        CHAR Text[RingTextBytes];
    } LOG_SLOT;

    static_assert(sizeof(LOG_SLOT) == RingLineBytes, "LOG_SLOT size mismatch");

    inline LOG_SLOT Ring[RingCapacity] = {};
    inline volatile LONG RingHead = 0;    // total lines ever appended
    inline volatile LONG RingDrained = 0; // total lines already drained

    inline size_t StrLenA(const char* s)
    {
        size_t n = 0;
        while (s[n])
            ++n;
        return n;
    }

    //
    // Appends one line to the ring.  Safe from any context; never waits,
    // never allocates, never faults (ring and stack are non-paged).
    //
    // The slot is marked empty while it is rewritten, so a drainer never
    // copies a torn line - it skips it instead.
    //
    inline void AppendLine(const char* text, size_t length)
    {
        if (!text)
            return;

        constexpr size_t maxLength = RingTextBytes - 2; // room for '\n' + NUL
        if (length > maxLength)
            length = maxLength;

        const LONG index = InterlockedIncrement(&RingHead) - 1;
        LOG_SLOT& slot = Ring[index & (RingCapacity - 1)];

        slot.Length = 0;
        MemoryBarrier();

        RtlCopyMemory(slot.Text, text, length);
        slot.Text[length] = '\n';
        slot.Text[length + 1] = '\0';

        MemoryBarrier();
        slot.Length = static_cast<LONG>(length + 1);
    }

    inline void Log(const char* step)
    {
        AppendLine(step, StrLenA(step));
    }

    inline void LogNum(const char* step, unsigned long long value)
    {
        char line[RingLineBytes];
        const size_t n = StrLenA(step);

        if (n >= sizeof(line) - 24)
        {
            //
            // The step text alone almost fills the slot (no call site is
            // anywhere near this long): keep the marker, drop the number.
            //
            AppendLine(step, n);
            return;
        }

        RtlCopyMemory(line, step, n);
        size_t l = n;
        line[l++] = ' ';

        char digits[24];
        int d = 0;
        if (value == 0)
        {
            line[l++] = '0';
        }
        else
        {
            while (value && d < 24)
            {
                digits[d++] = static_cast<char>('0' + static_cast<int>(value % 10));
                value /= 10;
            }
            while (d)
                line[l++] = digits[--d];
        }

        AppendLine(line, l);
    }

#if HYPERVISOR_LOG_ENABLE_FILE

    namespace Detail
    {
        //
        // Debug builds only.  Try the common drive letters and remember the
        // first one that works; \SystemRoot is the last resort (resolves
        // with no DOS-device lookup).  Only the flusher thread runs this
        // code, so the statics need no lock.  The file is created
        // FILE_WRITE_THROUGH so each drain is on disk before it returns.
        //
        inline bool WriteChunk(const char* data, const ULONG length)
        {
            static const WCHAR* paths[] = {
                L"\\??\\C:\\amager_hv.log",
                L"\\??\\D:\\amager_hv.log",
                L"\\??\\E:\\amager_hv.log",
                L"\\SystemRoot\\amager_hv.log",
            };
            constexpr long pathCount = sizeof(paths) / sizeof(paths[0]);
            static long chosen = -1;

            const long start = (chosen >= 0) ? chosen : 0;
            const long end = (chosen >= 0) ? (chosen + 1) : pathCount;

            for (long i = start; i < end; ++i)
            {
                HANDLE handle = nullptr;
                OBJECT_ATTRIBUTES attributes;
                UNICODE_STRING name;
                IO_STATUS_BLOCK ioStatus;

                RtlInitUnicodeString(&name, paths[i]);
                InitializeObjectAttributes(&attributes, &name, OBJ_KERNEL_HANDLE, nullptr, nullptr);

                if (!NT_SUCCESS(ZwCreateFile(&handle, FILE_APPEND_DATA | FILE_WRITE_EA, &attributes, &ioStatus,
                    nullptr, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN_IF,
                    FILE_SYNCHRONOUS_IO_NONALERT | FILE_WRITE_THROUGH, nullptr, 0)))
                {
                    continue;
                }

                ZwWriteFile(handle, nullptr, nullptr, nullptr, &ioStatus, const_cast<CHAR*>(data),
                    length, nullptr, nullptr);
                ZwClose(handle);

                if (chosen < 0)
                    chosen = i;

                return true;
            }

            return false;
        }

        //
        // Copies whole pending lines into `buffer` and returns the byte
        // count.  `from` is advanced past every slot it consumed or dropped.
        // A slot whose contents changed while being copied is dropped rather
        // than written torn.
        //
        inline ULONG GatherLines(LONG& from, const LONG head, char* buffer, const ULONG capacity)
        {
            ULONG used = 0;

            while (from < head)
            {
                const LOG_SLOT& slot = Ring[from & (RingCapacity - 1)];
                const LONG length = slot.Length;

                if (length <= 0 || static_cast<ULONG>(length) > RingTextBytes)
                {
                    ++from; // empty or mid-rewrite right now: drop it
                    continue;
                }

                if (used + static_cast<ULONG>(length) > capacity)
                    break;

                RtlCopyMemory(buffer + used, slot.Text, length);

                if (slot.Length != length)
                {
                    ++from; // rewritten while copying: drop the torn copy
                    continue;
                }

                used += static_cast<ULONG>(length);
                ++from;
            }

            return used;
        }
    }

    //
    // Writes every pending ring line to the log file.  Debug builds only;
    // only ever called from the flusher thread and from Entry() at boot
    // (PASSIVE_LEVEL, ordinary stack, interrupts enabled).
    //
    inline void FlushToFile()
    {
        for (;;)
        {
            const LONG head = RingHead;
            LONG from = RingDrained;

            if (from >= head)
                return;

            //
            // If writers lapped the drainer (the file path stalled while
            // exits kept logging), start at the oldest line still intact
            // instead of replaying overwritten slots.
            //
            if (head - from > static_cast<LONG>(RingCapacity))
                from = head - RingCapacity;

            char buffer[4096];
            const ULONG used = Detail::GatherLines(from, head, buffer, sizeof(buffer));

            if (used == 0)
                return; // every pending slot is mid-write; next tick retries

            if (!Detail::WriteChunk(buffer, used))
            {
                //
                // The file is not writable right now.  Leave RingDrained
                // alone so the lines are retried on the next tick instead of
                // being lost.
                //
                return;
            }

            InterlockedExchange(&RingDrained, from);
        }
    }

    //
    // The flusher thread: wakes twice a second and drains the ring to disk.
    // Debug builds only.
    //
    inline void LogFlusherThread(PVOID)
    {
        LARGE_INTEGER delay;
        delay.QuadPart = -5LL * 1000 * 100; // 500 ms, relative

        for (;;)
        {
            KeDelayExecutionThread(KernelMode, FALSE, &delay);
            FlushToFile();
        }
    }

    inline bool StartLogFlusher()
    {
        HANDLE threadHandle = nullptr;
        const NTSTATUS status = PsCreateSystemThread(&threadHandle, THREAD_ALL_ACCESS, nullptr, nullptr, nullptr, LogFlusherThread, nullptr);
        if (!NT_SUCCESS(status))
            return false;

        ZwClose(threadHandle);
        return true;
    }

#else // !HYPERVISOR_LOG_ENABLE_FILE

    //
    // Production: no file, no flusher thread.  The Entry() call sites stay
    // so re-enabling the flag restores the full debug behaviour.
    //
    inline void FlushToFile()
    {
    }

    inline bool StartLogFlusher()
    {
        return true;
    }

#endif
}
