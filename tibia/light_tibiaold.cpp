#include <iostream>
#include <Windows.h>
#include <string>
#include <tlhelp32.h>
#include <vector>
#include <psapi.h>

using namespace std;

vector<DWORD> GetPIDS(){
    std::vector<DWORD> pids;
    std::wstring targetProcessName = L"Tibia Old Client.exe";

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0); //all processes

    PROCESSENTRY32W entry; //current process
    entry.dwSize = sizeof entry;

    if (!Process32FirstW(snap, &entry))//start with the first in snapshot
        return pids;

    do {
        if (std::wstring(entry.szExeFile) == targetProcessName)
            pids.emplace_back(entry.th32ProcessID); //name matches; add to list
    } while (Process32NextW(snap, &entry)); //keep going until end of snapshot

    return pids;
}

uintptr_t GetModuleBaseAddress(DWORD dwProcID, char* szModuleName){
    uintptr_t ModuleBaseAddress = 0;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPALL, dwProcID);
    if (hSnapshot != INVALID_HANDLE_VALUE)
    {
        MODULEENTRY32 ModuleEntry32;
        ModuleEntry32.dwSize = sizeof(MODULEENTRY32);
        if (Module32First(hSnapshot, &ModuleEntry32))
        {
            do
            {
                if (strcmp(ModuleEntry32.szModule, szModuleName) == 0)
                {
                    ModuleBaseAddress = (uintptr_t)ModuleEntry32.modBaseAddr;
                    break;
                }
            } while (Module32Next(hSnapshot, &ModuleEntry32));
        }
        CloseHandle(hSnapshot);
    }
    return ModuleBaseAddress;
}

BOOL EnableDebugPrivilege(BOOL bEnable)
{
    HANDLE hToken = nullptr;
    LUID luid;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken)) return FALSE;
    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) return FALSE;

    TOKEN_PRIVILEGES tokenPriv;
    tokenPriv.PrivilegeCount = 1;
    tokenPriv.Privileges[0].Luid = luid;
    tokenPriv.Privileges[0].Attributes = bEnable ? SE_PRIVILEGE_ENABLED : 0;

    if (!AdjustTokenPrivileges(hToken, FALSE, &tokenPriv, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) return FALSE;

    return TRUE;
}


int main(int argc, char ** argv){
    DWORD pid;
    
    cout << EnableDebugPrivilege(true) << endl;

    vector<DWORD> pids = GetPIDS();

    for(int i=0;i<pids.size();i++){
        pid= pids[i];
        cout << "LIGHT HACK -> PID: " << pid << endl;
        HANDLE proc_handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
        if(!proc_handle){
            cout << "Failed to get process handler";
            break;
        }

        DWORD base = GetModuleBaseAddress(pid, (char*)"Tibia Old Client.exe");

        //subir descer escadas
        DWORD op_floor = base + 0xC928;

        /*unsigned char v[] = {0xB0, 0xD7,
                             0x0F, 0xB6, 0xD0,
                             0x89, 0x56, 0x74,
                             0xE8 ,0xEB, 0xFD, 0x0B, 0x00,//call
                             0x89, 0x56, 0x78,
                             0x90,
                             0xE8, 0x72, 0xFF, 0x0B, 0x00//call
                             };*/
        
        unsigned char v[] = {
            0xB0, 0x0A,                     //mov al,0a
            0x90,                           //nop
            0x88, 0x46, 0x74,               //mov [esi+74],al
            0xE8, 0xED, 0xFD, 0x0B, 0x00,   //call base+cc720
            0xB0, 0x56,                     //mov [esi+78], al
            0x90,                           //nop
            0x88, 0x46, 0x78,               //mov [esi+78], al
            0xE8, 0x72, 0xFF, 0x0B, 0x00    //call  base+cc8b0
        };

        SIZE_T written = 0;
        WriteProcessMemory(proc_handle, (void*)op_floor, &v, sizeof(v), &written);
        //cout << written << endl;


        //iluminacao gerada pelo player (tochas, magias, etc)
        DWORD op_torch = base + 0x0F758;
        unsigned char v2[] = {
            0xB0, 0x0A,
            0x90,
            0x88, 0x46, 0x74,
            0xE8, 0xBD, 0xCF, 0x0B, 0x00,
            0xB0, 0x56, 
            0x90,
            0x88, 0x46, 0x78
        };
        written = 0;
        WriteProcessMemory(proc_handle, (void*)op_torch, &v2, sizeof(v2), &written);
        //cout << written << endl;
        CloseHandle(proc_handle);
    }


    return 0;
}