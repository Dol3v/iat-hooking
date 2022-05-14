#include <Windows.h>
#include <stdio.h>

void injectDll(int pid, LPCSTR dllName) {
    // setup
    HANDLE hProcess = OpenProcess(
        PROCESS_ALL_ACCESS,
        FALSE,
        (DWORD) pid
    );
    if (hProcess == INVALID_HANDLE_VALUE) {
        printf("[injectDll] failed to open process %ld with error %x\n", pid, GetLastError());
        return;
    }

    HANDLE hKernelDll = GetModuleHandleA("KERNEL32.dll");
    if (hKernelDll == INVALID_HANDLE_VALUE) {
        printf("[injectDll] failed to open kernel32.dll with error %x\n", dllName, GetLastError());
        return;
    }

    // retrieving address of LoadLibraryA in process
    FARPROC loadLibraryAddress = GetProcAddress(hKernelDll, "LoadLibraryA");
    if (loadLibraryAddress == NULL) {
        printf("[injectDll] failed to get LoadLibraryA address from kernel32.dll with error %d\n", GetLastError());
        return;
    }

    // loading parameters for LoadLibraryA in the virtual memory of the victim process
    SIZE_T bufferLength = strlen(dllName) + 1;
    LPVOID buffer = VirtualAllocEx(
        hProcess,
        NULL,
        bufferLength,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE
    );
    if (buffer == NULL) {
        printf("[injectDll] failed to reserve memory in the process virtual address space with error %d\n", GetLastError());
        return;
    }
    if (!WriteProcessMemory(
        hProcess,
        buffer,
        dllName,
        bufferLength,
        NULL
    )) {
        printf("[injectDll] failed to write memory to allocated buffer with error %d\n", GetLastError());
        return;
    }

    // creating thread and running it
    HANDLE hThread = CreateRemoteThreadEx(
        hProcess,
        NULL,
        0, // default stack size
        loadLibraryAddress,
        buffer,
        0,
        NULL,
        NULL
    );

    if (hThread == INVALID_HANDLE_VALUE) {
        printf("[injectDll] failed to create remote thread with error %d\n", GetLastError());
        return;
    }
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        printf("Usage: inject <pid> <dllname>\n");
    }

    injectDll(atoi(argv[1]), argv[2]);
}
