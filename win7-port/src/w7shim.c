// w7shim.dll - implements the Windows 8+ / Win10+ APIs that opencode.exe imports
// but that don't exist on Windows 7 / Server 2016.
//
// All functions are implemented using Windows 7-compatible primitives:
//   - WaitOnAddress family uses CRITICAL_SECTION + CONDITION_VARIABLE (Vista+)
//   - GetSystemTimePreciseAsFileTime falls back to GetSystemTimeAsFileTime (Vista+)
//   - GetThreadDescription returns an empty string (no-op, debug-only API)
//   - ProcessPrng uses BCryptGenRandom (Vista+)
//
// This shim is loaded after opencode.exe's import table is patched so that
// the entries for api-ms-win-core-synch-l1-2-0.dll and bcryptprimitives.dll
// (and the redirected KERNEL32/ntdll entries via W7KERN3L.dll/w7ntd.dll)
// resolve here.

#include <windows.h>
#include <bcrypt.h>
#include <stdio.h>

// ---------------------------------------------------------------------------
// Per-address wait/wake implementation (replaces WaitOnAddress family)
// ---------------------------------------------------------------------------

typedef struct WaitNode {
    volatile void *address;
    CONDITION_VARIABLE cv;
    struct WaitNode *next;
} WaitNode;

static CRITICAL_SECTION g_wait_cs;
static WaitNode *g_wait_nodes = NULL;
static int g_initialized = 0;

static void ensure_init(void) {
    if (!g_initialized) {
        InitializeCriticalSection(&g_wait_cs);
        g_initialized = 1;
    }
}

static WaitNode *find_or_create_node(volatile void *address) {
    WaitNode *node = g_wait_nodes;
    while (node) {
        if (node->address == address) return node;
        node = node->next;
    }
    node = (WaitNode *)HeapAlloc(GetProcessHeap(), 0, sizeof(WaitNode));
    if (!node) return NULL;
    node->address = address;
    InitializeConditionVariable(&node->cv);
    node->next = g_wait_nodes;
    g_wait_nodes = node;
    return node;
}

// BOOL WaitOnAddress(volatile VOID *Address, PVOID CompareAddress, SIZE_T AddressSize, DWORD dwMilliseconds)
__declspec(dllexport) BOOL WINAPI WaitOnAddress(volatile VOID *Address, PVOID CompareAddress, SIZE_T AddressSize, DWORD dwMilliseconds) {
    ensure_init();
    EnterCriticalSection(&g_wait_cs);
    // If the value already differs from the comparand, return immediately.
    if (memcmp((const void *)Address, CompareAddress, AddressSize) != 0) {
        LeaveCriticalSection(&g_wait_cs);
        return TRUE;
    }
    WaitNode *node = find_or_create_node(Address);
    if (!node) {
        LeaveCriticalSection(&g_wait_cs);
        return FALSE;
    }
    BOOL ok = SleepConditionVariableCS(&node->cv, &g_wait_cs, dwMilliseconds);
    LeaveCriticalSection(&g_wait_cs);
    return ok;
}

// void WakeByAddressAll(PVOID Address)
__declspec(dllexport) void WINAPI WakeByAddressAll(PVOID Address) {
    ensure_init();
    EnterCriticalSection(&g_wait_cs);
    WaitNode *node = g_wait_nodes;
    while (node) {
        if (node->address == Address) {
            WakeAllConditionVariable(&node->cv);
            break;
        }
        node = node->next;
    }
    LeaveCriticalSection(&g_wait_cs);
}

// void WakeByAddressSingle(PVOID Address)
__declspec(dllexport) void WINAPI WakeByAddressSingle(PVOID Address) {
    ensure_init();
    EnterCriticalSection(&g_wait_cs);
    WaitNode *node = g_wait_nodes;
    while (node) {
        if (node->address == Address) {
            WakeConditionVariable(&node->cv);
            break;
        }
        node = node->next;
    }
    LeaveCriticalSection(&g_wait_cs);
}

// ntdll equivalents (same signatures, NTSTATUS return on RtlWaitOnAddress)
// RtlWaitOnAddress(volatile PVOID Address, PVOID CompareAddress, SIZE_T AddressSize, PLARGE_INTEGER Timeout)
__declspec(dllexport) NTSTATUS NTAPI RtlWaitOnAddress(volatile PVOID Address, PVOID CompareAddress, SIZE_T AddressSize, PLARGE_INTEGER Timeout) {
    DWORD ms = INFINITE;
    if (Timeout && Timeout->QuadPart < 0) {
        // Negative: relative 100ns intervals. Convert to ms.
        LONGLONG hundred_ns = -Timeout->QuadPart;
        ms = (DWORD)(hundred_ns / 10000);
    } else if (Timeout && Timeout->QuadPart > 0) {
        // Positive: absolute FILETIME. For simplicity, use INFINITE.
        ms = INFINITE;
    }
    if (WaitOnAddress(Address, CompareAddress, AddressSize, ms)) return 0;
    return (NTSTATUS)0xC000009A; // STATUS_NO_MEMORY, won't normally happen
}

__declspec(dllexport) void NTAPI RtlWakeAddressAll(PVOID Address) {
    WakeByAddressAll(Address);
}

__declspec(dllexport) void NTAPI RtlWakeAddressSingle(PVOID Address) {
    WakeByAddressSingle(Address);
}

// ---------------------------------------------------------------------------
// KERNEL32 replacements
// ---------------------------------------------------------------------------

// void GetSystemTimePreciseAsFileTime(LPFILETIME lpSystemTimeAsFileTime)
// Fall back to GetSystemTimeAsFileTime (lower resolution, but present since XP).
__declspec(dllexport) void WINAPI GetSystemTimePreciseAsFileTime(LPFILETIME lpSystemTimeAsFileTime) {
    GetSystemTimeAsFileTime(lpSystemTimeAsFileTime);
}

// HRESULT GetThreadDescription(HANDLE Thread, PWSTR *ppszThreadDescription)
// Return an empty string. GetThreadDescription is Win10 1607+ and used for
// debug thread naming; returning an empty string is a safe no-op.
__declspec(dllexport) HRESULT WINAPI GetThreadDescription(HANDLE Thread, PWSTR *ppszThreadDescription) {
    if (!ppszThreadDescription) return E_INVALIDARG;
    PWSTR empty = (PWSTR)LocalAlloc(LPTR, sizeof(WCHAR));
    if (!empty) return E_OUTOFMEMORY;
    *ppszThreadDescription = empty;
    return S_OK;
}

// ---------------------------------------------------------------------------
// KERNEL32 ConPTY stubs (Win10 1809+)
//
// ConPTY (Windows Pseudo Console) is the API opencode uses to spawn
// subprocesses with proper terminal emulation. On Win7 we cannot provide
// this functionality (it depends on a kernel-side ConPTY driver).
//
// Stubbed to return E_NOTIMPL / no-op. opencode.exe will still load and
// display its TUI; subprocess spawning via PTY may not work, but the
// server, LLM API calls, and core functionality still operate.
// ---------------------------------------------------------------------------

typedef PVOID HPCON;

__declspec(dllexport) HRESULT WINAPI CreatePseudoConsole(COORD size, HANDLE hInput, HANDLE hOutput, DWORD dwFlags, HPCON *phPC) {
    if (phPC) *phPC = NULL;
    return E_NOTIMPL;
}

__declspec(dllexport) void WINAPI ClosePseudoConsole(HPCON hPC) {
    // No-op
}

__declspec(dllexport) HRESULT WINAPI ResizePseudoConsole(HPCON hPC, COORD size) {
    return E_NOTIMPL;
}

// ---------------------------------------------------------------------------
// ntdll!RtlAddGrowableFunctionTable stub (Win8+)
//
// Used by Bun's JavaScriptCore JIT to register unwind info for JIT-compiled
// code. On Win7 we return failure. JavaScriptCore detects this and falls
// back to the CLoop interpreter. The opencode TUI and server run correctly
// in interpreter mode (slower JavaScript, but functional).
//
// Note: winnt.h declares this with DWORD return and ULONG_PTR range args
// (Win8+ SDK). We match that signature.
// ---------------------------------------------------------------------------

__declspec(dllexport) DWORD NTAPI RtlAddGrowableFunctionTable(
    PVOID *DynamicTable,
    PRUNTIME_FUNCTION FunctionTable,
    DWORD EntryCount,
    DWORD MaximumEntryCount,
    ULONG_PTR RangeBase,
    ULONG_PTR RangeEnd)
{
    if (DynamicTable) *DynamicTable = NULL;
    return (DWORD)0xC00000BB;  // STATUS_NOT_SUPPORTED - JSC will fall back to interpreter
}

// ---------------------------------------------------------------------------
// bcryptprimitives!ProcessPrng replacement
//
// ProcessPrng is an internal UCRT helper used to fetch random bytes for rand()
// and similar. It was added to bcryptprimitives.dll in Windows 10 1709.
// On Win7 / Server 2016 we delegate to BCryptGenRandom (Vista+).
// ---------------------------------------------------------------------------

static BCRYPT_ALG_HANDLE g_rng_handle = NULL;
static CRITICAL_SECTION g_rng_cs;
static int g_rng_initialized = 0;

static void ensure_rng_init(void) {
    if (!g_rng_initialized) {
        InitializeCriticalSection(&g_rng_cs);
        g_rng_initialized = 1;
    }
}

// BOOL ProcessPrng(PBYTE pbData, SIZE_T cbData)
// Returns TRUE on success, FALSE on failure (matches the original semantics).
__declspec(dllexport) BOOL WINAPI ProcessPrng(PBYTE pbData, SIZE_T cbData) {
    ensure_rng_init();
    if (!g_rng_handle) {
        EnterCriticalSection(&g_rng_cs);
        if (!g_rng_handle) {
            NTSTATUS st = BCryptOpenAlgorithmProvider(&g_rng_handle, BCRYPT_RNG_ALGORITHM, NULL, 0);
            if (st != 0) {
                LeaveCriticalSection(&g_rng_cs);
                return FALSE;
            }
        }
        LeaveCriticalSection(&g_rng_cs);
    }
    NTSTATUS st = BCryptGenRandom(g_rng_handle, pbData, (ULONG)cbData, 0);
    return st == 0;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
        case DLL_PROCESS_ATTACH:
            ensure_init();
            ensure_rng_init();
            DisableThreadLibraryCalls(hModule);
            break;
        case DLL_PROCESS_DETACH:
            if (g_rng_handle) {
                BCryptCloseAlgorithmProvider(g_rng_handle, 0);
                g_rng_handle = NULL;
            }
            break;
    }
    return TRUE;
}
