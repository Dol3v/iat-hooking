
Rem Builds the project

set PathToDll=hooking-dll
set DllMainFile=hookdll.c

Rem This function builds the hooking dll
:CreateDll
cd %PathToDll%
if not defined DevEnvDir (
    "C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\Common7\Tools\VsDevCmd.bat" && cl /LD %DllMainFile%
) else (
    cl /LD %DllMainFile%
)
exit /B 0   

@echo "Creating dll"
call CreateDll
@echo "Dll creation succeded"
