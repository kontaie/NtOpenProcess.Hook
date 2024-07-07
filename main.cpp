#include <iostream>
#include <Windows.h>
#include <winternl.h>

#ifdef _WIN64
uint8_t uTrampoline[] = {
    0x49, 0xBA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov r10, imm64
    0x41, 0xFF, 0xE2                                            // jmp r10
};
#else
uint8_t uTrampoline[] = {
    0xB8, 0x00, 0x00, 0x00, 0x00, // mov eax, imm32
    0xFF, 0xE0                    // jmp eax
};
#endif

typedef struct _CCLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID, * PCLIENT_ID;

typedef NTSTATUS(NTAPI* FTNtOpenProcess)(
    OUT PHANDLE             ProcessHandle,
    IN ACCESS_MASK          AccessMask,
    IN POBJECT_ATTRIBUTES   ObjectAttributes,
    IN PCLIENT_ID           ClientId
    ); 

FTNtOpenProcess ptNtOpenProcess = (FTNtOpenProcess)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtOpenProcess"); 

NTSTATUS NTAPI UnNtOpenProcess(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId) {
    if ((DesiredAccess & (PROCESS_ALL_ACCESS)) || (DesiredAccess & (PROCESS_SET_INFORMATION)) || (DesiredAccess & (PROCESS_QUERY_INFORMATION))) {
        DesiredAccess = PROCESS_QUERY_LIMITED_INFORMATION;
        return ptNtOpenProcess(ProcessHandle, DesiredAccess, ObjectAttributes, ClientId);
    }
}

int main() {
    DWORD dwOldProtection = 0;

    uint64_t uPatch = (uint64_t)&UnNtOpenProcess;
    memcpy(&uTrampoline[2], &uPatch, sizeof(uPatch));

    LPVOID targetAddress = (LPVOID)ptNtOpenProcess; 
    if (!VirtualProtect(targetAddress, sizeof(uTrampoline), PAGE_EXECUTE_READWRITE, &dwOldProtection)) {
        return FALSE;
    }

    memcpy(targetAddress, uTrampoline, sizeof(uTrampoline));

    VirtualProtect(targetAddress, sizeof(uTrampoline), dwOldProtection, &dwOldProtection);

    return 0;
}
