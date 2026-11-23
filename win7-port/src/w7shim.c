// w7shim.dll - implements the Windows 8+ / Win10+ APIs that opencode.exe imports
// but that don't exist on Windows 7 / Server 2016.
//
// KEY DESIGN: Dynamic forwarding. For each shimmed function, we first try to
// load it from the REAL system DLL. If the native implementation exists
// (e.g., on Server 2016, which has WaitOnAddress natively), we forward to it.
// Only on Windows 7 (where the native doesn't exist) do we fall back to our
// own implementation using Vista-era primitives.
//
// This fixes the crash on Server 2016 where our buggy shim was replacing a
// working native WaitOnAddress.

#include <windows.h>
#include <bcrypt.h>

// ---------------------------------------------------------------------------
// NTSTATUS codes
// ---------------------------------------------------------------------------
#define STATUS_SUCCESS              ((NTSTATUS)0x00000000L)
#define STATUS_TIMEOUT               ((NTSTATUS)0x00000102L)
#define STATUS_NO_MEMORY             ((NTSTATUS)0xC000009AL)
#define STATUS_NOT_SUPPORTED         ((NTSTATUS)0xC00000BBL)
#define STATUS_UNSUCCESSFUL          ((NTSTATUS)0xC0000001L)

// ---------------------------------------------------------------------------
// Dynamic forwarding helper
//
// Tries to resolve a function from the real system DLL. Caches the result
// in a static variable so subsequent calls are fast (just a pointer check).
// ---------------------------------------------------------------------------

// Resolve a function from a DLL by name. Returns NULL if not found.
static FARPROC resolve_function(LPCSTR dll_name, LPCSTR func_name) {
    // Try GetModuleHandle first (DLL might already be loaded)
    HMODULE h = GetModuleHandleA(dll_name);
    if (!h) {
        // Try loading it
        h = LoadLibraryA(dll_name);
    }
    if (!h) return NULL;
    return GetProcAddress(h, func_name);
}

// ---------------------------------------------------------------------------
// Per-address wait/wake implementation (fallback for Win7 where native
// WaitOnAddress doesn't exist)
//
// Uses CRITICAL_SECTION + CONDITION_VARIABLE (both Vista+).
// ---------------------------------------------------------------------------

typedef struct WaitNode {
    volatile void *address;
    CONDITION_VARIABLE cv;
    struct WaitNode *next;
} WaitNode;

static CRITICAL_SECTION g_wait_cs;
static WaitNode *g_wait_nodes = NULL;
static int g_wait_initialized = 0;

static void ensure_wait_init(void) {
    if (!g_wait_initialized) {
        InitializeCriticalSection(&g_wait_cs);
        g_wait_initialized = 1;
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

// Fallback implementation of WaitOnAddress for Win7.
// Returns TRUE if the value changed, FALSE on timeout/error.
static BOOL WINAPI fallback_WaitOnAddress(
    volatile VOID *Address,
    PVOID CompareAddress,
    SIZE_T AddressSize,
    DWORD dwMilliseconds)
{
    ensure_wait_init();
    EnterCriticalSection(&g_wait_cs);

    DWORD start_tick = GetTickCount();
    BOOL result = FALSE;

    // Loop: check value, wait if it still matches, re-check after wake.
    // This handles spurious wakeups correctly.
    for (;;) {
        // If the value already differs from the comparand, return TRUE.
        if (memcmp((const void *)Address, CompareAddress, AddressSize) != 0) {
            result = TRUE;
            break;
        }

        // Check if we've timed out
        if (dwMilliseconds != INFINITE) {
            DWORD elapsed = GetTickCount() - start_tick;
            if (elapsed >= dwMilliseconds) {
                // Timed out
                SetLastError(WAIT_TIMEOUT);
                result = FALSE;
                break;
            }
        }

        WaitNode *node = find_or_create_node(Address);
        if (!node) {
            SetLastError(ERROR_NOT_ENOUGH_MEMORY);
            result = FALSE;
            break;
        }

        // Compute remaining time
        DWORD remaining = INFINITE;
        if (dwMilliseconds != INFINITE) {
            DWORD elapsed = GetTickCount() - start_tick;
            if (elapsed >= dwMilliseconds) {
                SetLastError(WAIT_TIMEOUT);
                result = FALSE;
                break;
            }
            remaining = dwMilliseconds - elapsed;
        }

        // Wait on the condition variable. Returns FALSE on timeout.
        SleepConditionVariableCS(&node->cv, &g_wait_cs, remaining);
        // Loop back and re-check the value.
    }

    LeaveCriticalSection(&g_wait_cs);
    return result;
}

static void WINAPI fallback_WakeByAddressAll(PVOID Address) {
    ensure_wait_init();
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

static void WINAPI fallback_WakeByAddressSingle(PVOID Address) {
    ensure_wait_init();
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

// ---------------------------------------------------------------------------
// WaitOnAddress family — exported functions
//
// These try the native implementation first (from api-ms-win-core-synch-l1-2-0.dll),
// and fall back to our Win7-compatible implementation if the native doesn't exist.
// ---------------------------------------------------------------------------

typedef BOOL (WINAPI *WaitOnAddress_t)(volatile VOID *, PVOID, SIZE_T, DWORD);
typedef void (WINAPI *WakeByAddressAll_t)(PVOID);
typedef void (WINAPI *WakeByAddressSingle_t)(PVOID);

static WaitOnAddress_t g_real_WaitOnAddress = NULL;
static WakeByAddressAll_t g_real_WakeByAddressAll = NULL;
static WakeByAddressSingle_t g_real_WakeByAddressSingle = NULL;
static int g_synch_resolved = 0;

static void resolve_synch(void) {
    if (!g_synch_resolved) {
        g_synch_resolved = 1;
        HMODULE h = GetModuleHandleA("api-ms-win-core-synch-l1-2-0.dll");
        if (!h) h = LoadLibraryA("api-ms-win-core-synch-l1-2-0.dll");
        if (h) {
            g_real_WaitOnAddress = (WaitOnAddress_t)GetProcAddress(h, "WaitOnAddress");
            g_real_WakeByAddressAll = (WakeByAddressAll_t)GetProcAddress(h, "WakeByAddressAll");
            g_real_WakeByAddressSingle = (WakeByAddressSingle_t)GetProcAddress(h, "WakeByAddressSingle");
        }
    }
}

__declspec(dllexport) BOOL WINAPI WaitOnAddress(
    volatile VOID *Address, PVOID CompareAddress,
    SIZE_T AddressSize, DWORD dwMilliseconds)
{
    resolve_synch();
    if (g_real_WaitOnAddress) {
        return g_real_WaitOnAddress(Address, CompareAddress, AddressSize, dwMilliseconds);
    }
    return fallback_WaitOnAddress(Address, CompareAddress, AddressSize, dwMilliseconds);
}

__declspec(dllexport) void WINAPI WakeByAddressAll(PVOID Address) {
    resolve_synch();
    if (g_real_WakeByAddressAll) {
        g_real_WakeByAddressAll(Address);
        return;
    }
    fallback_WakeByAddressAll(Address);
}

__declspec(dllexport) void WINAPI WakeByAddressSingle(PVOID Address) {
    resolve_synch();
    if (g_real_WakeByAddressSingle) {
        g_real_WakeByAddressSingle(Address);
        return;
    }
    fallback_WakeByAddressSingle(Address);
}

// ---------------------------------------------------------------------------
// ntdll equivalents (RtlWaitOnAddress family)
//
// These are the ntdll versions with NTSTATUS return codes. Bun calls these
// directly and checks for STATUS_SUCCESS (0) or STATUS_TIMEOUT (0x102).
//
// We try the native ntdll implementation first, then fall back to our
// Win7-compatible implementation.
// ---------------------------------------------------------------------------

typedef NTSTATUS (NTAPI *RtlWaitOnAddress_t)(volatile PVOID, PVOID, SIZE_T, PLARGE_INTEGER);
typedef void (NTAPI *RtlWakeAddressAll_t)(PVOID);
typedef void (NTAPI *RtlWakeAddressSingle_t)(PVOID);

static RtlWaitOnAddress_t g_real_RtlWaitOnAddress = NULL;
static RtlWakeAddressAll_t g_real_RtlWakeAddressAll = NULL;
static RtlWakeAddressSingle_t g_real_RtlWakeAddressSingle = NULL;
static int g_rtl_synch_resolved = 0;

static void resolve_rtl_synch(void) {
    if (!g_rtl_synch_resolved) {
        g_rtl_synch_resolved = 1;
        HMODULE h = GetModuleHandleA("ntdll.dll");
        if (h) {
            g_real_RtlWaitOnAddress = (RtlWaitOnAddress_t)GetProcAddress(h, "RtlWaitOnAddress");
            g_real_RtlWakeAddressAll = (RtlWakeAddressAll_t)GetProcAddress(h, "RtlWakeAddressAll");
            g_real_RtlWakeAddressSingle = (RtlWakeAddressSingle_t)GetProcAddress(h, "RtlWakeAddressSingle");
        }
    }
}

// Convert a LARGE_INTEGER timeout (Win32 NT-style) to a DWORD milliseconds.
// NULL timeout = INFINITE.
// Negative = relative 100ns intervals.
// Positive = absolute FILETIME.
// Zero = no wait (test once).
static DWORD timeout_to_ms(PLARGE_INTEGER Timeout) {
    if (!Timeout) return INFINITE;
    LONGLONG v = Timeout->QuadPart;
    if (v == 0) return 0;  // Test once, no wait
    if (v < 0) {
        // Relative: 100ns units. Convert to ms.
        LONGLONG hundred_ns = -v;
        LONGLONG ms = hundred_ns / 10000;
        if (ms == 0) ms = 1;
        if (ms > 0xFFFFFFFF) return 0xFFFFFFFF;
        return (DWORD)ms;
    }
    // Positive: absolute FILETIME. Compute remaining time.
    FILETIME now_ft;
    GetSystemTimeAsFileTime(&now_ft);
    ULARGE_INTEGER now;
    now.LowPart = now_ft.dwLowDateTime;
    now.HighPart = now_ft.dwHighDateTime;
    LONGLONG remaining = v - now.QuadPart;
    if (remaining <= 0) return 0;
    LONGLONG ms = remaining / 10000;
    if (ms == 0) ms = 1;
    if (ms > 0xFFFFFFFF) return 0xFFFFFFFF;
    return (DWORD)ms;
}

__declspec(dllexport) NTSTATUS NTAPI RtlWaitOnAddress(
    volatile PVOID Address, PVOID CompareAddress,
    SIZE_T AddressSize, PLARGE_INTEGER Timeout)
{
    resolve_rtl_synch();
    if (g_real_RtlWaitOnAddress) {
        return g_real_RtlWaitOnAddress(Address, CompareAddress, AddressSize, Timeout);
    }

    // Fallback: use our WaitOnAddress and convert the result to NTSTATUS
    DWORD ms = timeout_to_ms(Timeout);
    BOOL ok = fallback_WaitOnAddress(Address, CompareAddress, AddressSize, ms);
    if (ok) {
        return STATUS_SUCCESS;  // 0
    }
    DWORD err = GetLastError();
    if (err == WAIT_TIMEOUT) {
        return STATUS_TIMEOUT;  // 0x00000102
    }
    return STATUS_UNSUCCESSFUL;  // 0xC0000001
}

__declspec(dllexport) void NTAPI RtlWakeAddressAll(PVOID Address) {
    resolve_rtl_synch();
    if (g_real_RtlWakeAddressAll) {
        g_real_RtlWakeAddressAll(Address);
        return;
    }
    fallback_WakeByAddressAll(Address);
}

__declspec(dllexport) void NTAPI RtlWakeAddressSingle(PVOID Address) {
    resolve_rtl_synch();
    if (g_real_RtlWakeAddressSingle) {
        g_real_RtlWakeAddressSingle(Address);
        return;
    }
    fallback_WakeByAddressSingle(Address);
}

// ---------------------------------------------------------------------------
// KERNEL32: GetSystemTimePreciseAsFileTime (Win8+)
//
// Forward to native if available (Server 2016+), else fall back to
// GetSystemTimeAsFileTime.
// ---------------------------------------------------------------------------

typedef void (WINAPI *GetSystemTimePreciseAsFileTime_t)(LPFILETIME);
static GetSystemTimePreciseAsFileTime_t g_real_GetSystemTimePreciseAsFileTime = NULL;
static int g_kern_resolved = 0;

static void resolve_kern(void) {
    if (!g_kern_resolved) {
        g_kern_resolved = 1;
        HMODULE h = GetModuleHandleA("KERNEL32.dll");
        if (h) {
            g_real_GetSystemTimePreciseAsFileTime = (GetSystemTimePreciseAsFileTime_t)
                GetProcAddress(h, "GetSystemTimePreciseAsFileTime");
        }
    }
}

__declspec(dllexport) void WINAPI GetSystemTimePreciseAsFileTime(LPFILETIME lpSystemTimeAsFileTime) {
    resolve_kern();
    if (g_real_GetSystemTimePreciseAsFileTime) {
        g_real_GetSystemTimePreciseAsFileTime(lpSystemTimeAsFileTime);
        return;
    }
    // Fallback: lower resolution (Win7)
    GetSystemTimeAsFileTime(lpSystemTimeAsFileTime);
}

// ---------------------------------------------------------------------------
// KERNEL32: GetThreadDescription (Win10 1607+)
//
// On Server 2016 (build 14393 = Win10 1607), this exists natively.
// Forward to it. On Win7, return an empty string.
// ---------------------------------------------------------------------------

typedef HRESULT (WINAPI *GetThreadDescription_t)(HANDLE, PWSTR *);
static GetThreadDescription_t g_real_GetThreadDescription = NULL;

__declspec(dllexport) HRESULT WINAPI GetThreadDescription(HANDLE Thread, PWSTR *ppszThreadDescription) {
    if (!g_real_GetThreadDescription) {
        HMODULE h = GetModuleHandleA("KERNEL32.dll");
        if (h) {
            g_real_GetThreadDescription = (GetThreadDescription_t)
                GetProcAddress(h, "GetThreadDescription");
        }
    }
    if (g_real_GetThreadDescription) {
        return g_real_GetThreadDescription(Thread, ppszThreadDescription);
    }
    // Fallback (Win7): return an empty string
    if (!ppszThreadDescription) return E_INVALIDARG;
    PWSTR empty = (PWSTR)LocalAlloc(LPTR, sizeof(WCHAR));
    if (!empty) return E_OUTOFMEMORY;
    *ppszThreadDescription = empty;
    return S_OK;
}

// ---------------------------------------------------------------------------
// KERNEL32 ConPTY stubs (Win10 1809+)
//
// These do NOT exist on Server 2016 (build 14393). We check dynamically
// and forward to the native implementation if available (Win10 1809+).
// Otherwise, return E_NOTIMPL.
// ---------------------------------------------------------------------------

typedef PVOID HPCON;

typedef HRESULT (WINAPI *CreatePseudoConsole_t)(COORD, HANDLE, HANDLE, DWORD, HPCON *);
typedef void (WINAPI *ClosePseudoConsole_t)(HPCON);
typedef HRESULT (WINAPI *ResizePseudoConsole_t)(HPCON, COORD);

static CreatePseudoConsole_t g_real_CreatePseudoConsole = NULL;
static ClosePseudoConsole_t g_real_ClosePseudoConsole = NULL;
static ResizePseudoConsole_t g_real_ResizePseudoConsole = NULL;
static int g_conpty_resolved = 0;

static void resolve_conpty(void) {
    if (!g_conpty_resolved) {
        g_conpty_resolved = 1;
        HMODULE h = GetModuleHandleA("KERNEL32.dll");
        if (h) {
            g_real_CreatePseudoConsole = (CreatePseudoConsole_t)
                GetProcAddress(h, "CreatePseudoConsole");
            g_real_ClosePseudoConsole = (ClosePseudoConsole_t)
                GetProcAddress(h, "ClosePseudoConsole");
            g_real_ResizePseudoConsole = (ResizePseudoConsole_t)
                GetProcAddress(h, "ResizePseudoConsole");
        }
    }
}

__declspec(dllexport) HRESULT WINAPI CreatePseudoConsole(
    COORD size, HANDLE hInput, HANDLE hOutput, DWORD dwFlags, HPCON *phPC)
{
    resolve_conpty();
    if (g_real_CreatePseudoConsole) {
        return g_real_CreatePseudoConsole(size, hInput, hOutput, dwFlags, phPC);
    }
    // Fallback: not supported on Win7 / Server 2016
    if (phPC) *phPC = NULL;
    return E_NOTIMPL;
}

__declspec(dllexport) void WINAPI ClosePseudoConsole(HPCON hPC) {
    resolve_conpty();
    if (g_real_ClosePseudoConsole) {
        g_real_ClosePseudoConsole(hPC);
        return;
    }
    // Fallback: no-op
}

__declspec(dllexport) HRESULT WINAPI ResizePseudoConsole(HPCON hPC, COORD size) {
    resolve_conpty();
    if (g_real_ResizePseudoConsole) {
        return g_real_ResizePseudoConsole(hPC, size);
    }
    return E_NOTIMPL;
}

// ---------------------------------------------------------------------------
// ntdll: RtlAddGrowableFunctionTable (Win8+)
//
// On Server 2016 (Win8+), this exists natively. Forward to it so
// JavaScriptCore can use the JIT. On Win7, return STATUS_NOT_SUPPORTED
// so JSC falls back to the CLoop interpreter.
// ---------------------------------------------------------------------------

typedef DWORD (NTAPI *RtlAddGrowableFunctionTable_t)(
    PVOID *, PRUNTIME_FUNCTION, DWORD, DWORD, ULONG_PTR, ULONG_PTR);
typedef void (NTAPI *RtlDeleteGrowableFunctionTable_t)(PVOID *);

static RtlAddGrowableFunctionTable_t g_real_RtlAddGrowableFunctionTable = NULL;
static int g_rtl_table_resolved = 0;

static void resolve_rtl_table(void) {
    if (!g_rtl_table_resolved) {
        g_rtl_table_resolved = 1;
        HMODULE h = GetModuleHandleA("ntdll.dll");
        if (h) {
            g_real_RtlAddGrowableFunctionTable = (RtlAddGrowableFunctionTable_t)
                GetProcAddress(h, "RtlAddGrowableFunctionTable");
        }
    }
}

__declspec(dllexport) DWORD NTAPI RtlAddGrowableFunctionTable(
    PVOID *DynamicTable,
    PRUNTIME_FUNCTION FunctionTable,
    DWORD EntryCount,
    DWORD MaximumEntryCount,
    ULONG_PTR RangeBase,
    ULONG_PTR RangeEnd)
{
    resolve_rtl_table();
    if (g_real_RtlAddGrowableFunctionTable) {
        return g_real_RtlAddGrowableFunctionTable(
            DynamicTable, FunctionTable, EntryCount, MaximumEntryCount,
            RangeBase, RangeEnd);
    }
    // Fallback (Win7): JSC will fall back to CLoop interpreter
    if (DynamicTable) *DynamicTable = NULL;
    return (DWORD)STATUS_NOT_SUPPORTED;
}

// ---------------------------------------------------------------------------
// bcryptprimitives: ProcessPrng (Win10 1709+)
//
// This NEVER exists on Win7 or Server 2016 (build 14393 < 16299).
// Always use our BCryptGenRandom-based implementation.
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

__declspec(dllexport) BOOL WINAPI ProcessPrng(PBYTE pbData, SIZE_T cbData) {
    ensure_rng_init();
    if (!g_rng_handle) {
        EnterCriticalSection(&g_rng_cs);
        if (!g_rng_handle) {
            NTSTATUS st = BCryptOpenAlgorithmProvider(
                &g_rng_handle, BCRYPT_RNG_ALGORITHM, NULL, 0);
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

// ---------------------------------------------------------------------------
// DllMain
// ---------------------------------------------------------------------------

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
        case DLL_PROCESS_ATTACH:
            ensure_wait_init();
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
