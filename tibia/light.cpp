#include <iostream>
#include <Windows.h>
#include <string>
#include <tlhelp32.h>
#include <vector>
#include <psapi.h>

using namespace std;

vector<DWORD> GetPIDS(){
    std::vector<DWORD> pids;
    std::wstring targetProcessName = L"Capernia_OGL.exe";

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


int main(int argc, char ** argv){
    DWORD pid;
    DWORD access = PROCESS_VM_READ | PROCESS_QUERY_INFORMATION| PROCESS_VM_WRITE | PROCESS_VM_OPERATION;

    vector<DWORD> pids = GetPIDS();

    for(int i=0;i<pids.size();i++){
        pid= pids[i];
        cout << "LIGHT HACK -> PID: " << pid << endl;
        HANDLE proc_handle = OpenProcess(access, 0, pid);
        if(!proc_handle){
            cout << "Failed to get process handler";
            break;
        }
        //modifica luz atual
        DWORD base = GetModuleBaseAddress(pid, (char*)"Capernia_OGL.exe");
        DWORD light = base + 0x0082A960;
        DWORD offset = 0xA0;
        DWORD ptr = 0;
        ReadProcessMemory(proc_handle, (void*)light, &ptr, sizeof(ptr), NULL);
        int val = 0xD7FF;
        WriteProcessMemory(proc_handle, (void*)(ptr + offset), &val, sizeof(val), NULL);

        //subir descer escadas
        DWORD op_floor_color = base + 0x140B5D; //6 bytes    B1 D7 90 90 90 90
        DWORD op_floor_power = base + 0x140B51; //6 bytes    B1 FF 90 90 90 90
        unsigned char v[6] = {0xB1, 0xD7, 0x90, 0x90, 0x90, 0x90};
        SIZE_T written = 0;
        WriteProcessMemory(proc_handle, (void*)op_floor_color, &v, sizeof(v), &written);
        //cout << written << endl;

        v[1] = 0xFF;
        written = 0;
        WriteProcessMemory(proc_handle, (void*)op_floor_power, &v, sizeof(v), &written);
        //cout << written << endl;

        //iluminacao gerada pelo player (tochas, magias, etc)
        DWORD op_torch = base + 0x13339F;
        unsigned char v2[12] = {0xC7, 0x80, 0xA0, 0x00, 0x00, 0x00, 0xFF, 0xD7, 0x00, 0x00, 0x90, 0x90};
        written = 0;
        WriteProcessMemory(proc_handle, (void*)op_torch, &v2, sizeof(v2), &written);
        //cout << written << endl;
    }
    
    return 0;
}