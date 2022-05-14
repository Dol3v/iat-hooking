#pragma once
#include <Windows.h>
#pragma comment(lib, "user32.lib")

#ifdef DLL_EXPORT
#define DECLDIR __declspec(dllexport)
#else
#define DECLDIR __declspec(dllimport)
#endif

#define DLL_TO_HOOK "KERNEL32.dll"
#define FUNCTION_TO_HOOK "CreateFileA"

HANDLE hookedCreateFileA(LPCSTR fileName, DWORD desiredAccess, DWORD sharedMode, LPSECURITY_ATTRIBUTES securityAttributes,
    DWORD creationDisposition, DWORD flags, HANDLE templateFile);
PIMAGE_IMPORT_DESCRIPTOR getImportDescriptor(DWORD baseAddress);
void hook();
