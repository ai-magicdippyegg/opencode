// Stub DllMain for forwarding DLLs (W7KERN3L.dll, w7ntd.dll).
// All exports are forwarders defined in the .def file.
#include <windows.h>
BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID lpReserved) {
    switch (reason) {
        case DLL_PROCESS_ATTACH:
            DisableThreadLibraryCalls(hModule);
            break;
    }
    return TRUE;
}
