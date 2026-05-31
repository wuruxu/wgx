#include "wintun_loader.h"

WINTUN_CREATE_ADAPTER_FUNC *WintunCreateAdapter;
WINTUN_CLOSE_ADAPTER_FUNC *WintunCloseAdapter;
WINTUN_OPEN_ADAPTER_FUNC *WintunOpenAdapter;
WINTUN_GET_ADAPTER_LUID_FUNC *WintunGetAdapterLUID;
WINTUN_GET_RUNNING_DRIVER_VERSION_FUNC *WintunGetRunningDriverVersion;
WINTUN_SET_LOGGER_FUNC *WintunSetLogger;
WINTUN_START_SESSION_FUNC *WintunStartSession;
WINTUN_END_SESSION_FUNC *WintunEndSession;
WINTUN_GET_READ_WAIT_EVENT_FUNC *WintunGetReadWaitEvent;
WINTUN_RECEIVE_PACKET_FUNC *WintunReceivePacket;
WINTUN_RELEASE_RECEIVE_PACKET_FUNC *WintunReleaseReceivePacket;
WINTUN_ALLOCATE_SEND_PACKET_FUNC *WintunAllocateSendPacket;
WINTUN_SEND_PACKET_FUNC *WintunSendPacket;

HMODULE wgx_wintun_load(void)
{
    HMODULE module = LoadLibraryExW(L"wintun.dll", NULL,
                                    LOAD_LIBRARY_SEARCH_APPLICATION_DIR |
                                    LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (!module)
        return NULL;

#define WGX_LOAD_PROC(Name) ((*(FARPROC *)&Name = GetProcAddress(module, #Name)) == NULL)
    if (WGX_LOAD_PROC(WintunCreateAdapter) ||
        WGX_LOAD_PROC(WintunCloseAdapter) ||
        WGX_LOAD_PROC(WintunOpenAdapter) ||
        WGX_LOAD_PROC(WintunGetAdapterLUID) ||
        WGX_LOAD_PROC(WintunGetRunningDriverVersion) ||
        WGX_LOAD_PROC(WintunSetLogger) ||
        WGX_LOAD_PROC(WintunStartSession) ||
        WGX_LOAD_PROC(WintunEndSession) ||
        WGX_LOAD_PROC(WintunGetReadWaitEvent) ||
        WGX_LOAD_PROC(WintunReceivePacket) ||
        WGX_LOAD_PROC(WintunReleaseReceivePacket) ||
        WGX_LOAD_PROC(WintunAllocateSendPacket) ||
        WGX_LOAD_PROC(WintunSendPacket)) {
#undef WGX_LOAD_PROC
        DWORD last_error = GetLastError();
        FreeLibrary(module);
        SetLastError(last_error);
        return NULL;
    }

    return module;
}

void wgx_wintun_unload(HMODULE module)
{
    if (module)
        FreeLibrary(module);
}

