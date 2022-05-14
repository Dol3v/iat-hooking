#include "hookdll.h"
#include <stdio.h>

#define ONE_TIME_HOOK

DWORD prevFuncPointer = 0;

/// Hooked CreateFileA
HANDLE hookedCreateFileA(LPCSTR fileName, DWORD desiredAccess, DWORD sharedMode, LPSECURITY_ATTRIBUTES securityAttributes,
    DWORD creationDisposition, DWORD flags, HANDLE templateFile) {
    MessageBoxA(NULL, "You have been hooked;)", "IAT Hook", MB_OK);
    #ifdef ONE_TIME_HOOK
    hook(DLL_TO_HOOK, FUNCTION_TO_HOOK, prevFuncPointer);
    #endif
    return CreateFileA(fileName, desiredAccess, sharedMode, securityAttributes, creationDisposition, flags, templateFile);
}

/// Gets the import descriptor of a process with a given base address
PIMAGE_IMPORT_DESCRIPTOR getImportDescriptor(DWORD baseAddress) {
    PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER) baseAddress;
    printf("[getImportDescriptor] verifying DOS header signature\n");
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        return NULL;
    }

    PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS) (baseAddress + pDosHeader->e_lfanew);
    printf("[getImportDescriptor] verifying NT header signature\n");
    if (pNtHeader->Signature != IMAGE_NT_SIGNATURE) {
        return NULL;
    }

    PIMAGE_OPTIONAL_HEADER pOptionalHeader = (PIMAGE_OPTIONAL_HEADER) &pNtHeader->OptionalHeader;
    printf("[getImportDescritptor] verifying optional header signature\n");
    if (pOptionalHeader->Magic != 0x10B) {
        return NULL;
    }

    IMAGE_DATA_DIRECTORY importDirectory = pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(importDirectory.VirtualAddress + baseAddress);
    return pImportDescriptor;
}

/// Hooks the function that is found in this dll
BOOL hookDescriptor(IMAGE_IMPORT_DESCRIPTOR importDescriptor, LPCSTR funcNameToHook, DWORD newFunctionPointer, DWORD baseAddress) {
    PIMAGE_THUNK_DATA iat = (PIMAGE_THUNK_DATA) (importDescriptor.FirstThunk + baseAddress);
    PIMAGE_THUNK_DATA ilt = (PIMAGE_THUNK_DATA) (importDescriptor.OriginalFirstThunk + baseAddress);

    // finding actual function in dll
    printf("[hookDescriptor] scanning ILT for function name\n");
    PIMAGE_IMPORT_BY_NAME pNameData;
    while (ilt->u1.AddressOfData != 0) {
        pNameData = (PIMAGE_IMPORT_BY_NAME) (ilt->u1.AddressOfData + baseAddress);
        printf("[hookDescriptor] scanning function %s\n", (char*)(pNameData->Name));
        if (strcmp((char*) (pNameData->Name), funcNameToHook) == 0) {
            printf("[hookDescriptor] found the function to hook\n");
            // changing the function address in the (probably read only memory) IAT
            DWORD prevPerms = 0;
            prevFuncPointer = iat->u1.Function;
            VirtualProtect((LPVOID)(&iat->u1.Function), sizeof(DWORD), PAGE_READWRITE, &prevPerms);
            iat->u1.Function = newFunctionPointer;
            VirtualProtect((LPVOID)(&iat->u1.Function), sizeof(DWORD), prevPerms, NULL);
            printf("[hookDescriptor] modified IAT\n"); 
            return TRUE;
        }
        ilt++;
        iat++;
    }
    printf("[hookDescriptor] didn't find the function %s in the ILT, hook failed\n", FUNCTION_TO_HOOK);
    return FALSE;
}

/// Hooks 
void hook(LPCSTR dllNameToHook, LPCSTR funcNameToHook, DWORD newFunctionAddress) {
    DWORD baseAddress = (DWORD) GetModuleHandle(NULL);
    PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor = getImportDescriptor(baseAddress);

    if (!pImportDescriptor) {
        printf("[hook] couldn't get import descriptor of process with base address %ld\n", baseAddress);
    }

    int entryIndex = 0;
    // looping over all imported dlls
    printf("[hook] scanning DLLS\n");
    while (pImportDescriptor[entryIndex].Characteristics != 0) {
        char* dllName = (char*) (pImportDescriptor[entryIndex].Name + baseAddress);
        printf("[hook] got dll %s\n", dllName);
        if (dllName && strcmp(dllName, dllNameToHook) == 0) {
            printf("[hook] found DLL %s\n", dllName);
            if (hookDescriptor(pImportDescriptor[entryIndex], funcNameToHook, newFunctionAddress, baseAddress)) {
                printf("[hook] hook successful\n");
            } else {
                printf("[hook] hook failed\n");
            }
            break;
        }
        entryIndex++; 
    }
    
}

BOOL APIENTRY DllMain(HANDLE hModule, //handle to DLL module
                    DWORD ul_reason_for_call,
                    LPVOID reserved) {
    switch (ul_reason_for_call) {
        case DLL_PROCESS_ATTACH:
            hook(DLL_TO_HOOK, FUNCTION_TO_HOOK, (DWORD) hookedCreateFileA);
            break;
        case DLL_THREAD_ATTACH:
        case DLL_THREAD_DETACH:
        case DLL_PROCESS_DETACH:
            break;
    }
    return TRUE;
}
