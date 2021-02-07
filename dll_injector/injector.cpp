#include <windows.h> 
#include <tlhelp32.h> 
#include <shlwapi.h> 
#include <conio.h> 
#include <stdio.h> 


#define WIN32_LEAN_AND_MEAN 
#define CREATE_THREAD_ACCESS (PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ) 

BOOL Inject(DWORD pID, const char * DLL_NAME); 
DWORD GetTargetThreadIDFromProcName(const char * ProcName); 

int main(int argc, char * argv[]) 
{ 
   DWORD pID;
   char buf[MAX_PATH] = {0};
   if(argc <2 || argc >3){
      printf("Usage(1) : %s \"name.dll\" \"program.exe\"\n", argv[0]);
      printf("Usage(2) : %s \"name.dll\"\t*\t inject to default program (check \'default.cfg\' file).\n", argv[0]);
      return -1;
   }
   else if (argc == 2){
      FILE * fp = fopen("default.cfg", "r");
      if(!fp){
         printf("Sorry, file \'default.cfg\' not found in this directory.\n");
         printf("try writing a new one with your text editor, inside the file\nyou should write: program_name.exe\n");
         return -1;
      }
      char name[260]; // windows max file name length
      memset(name,'\0',260);
      fgets(name,260, fp);
      fclose(fp);
      pID = GetTargetThreadIDFromProcName(name); 
      GetFullPathName(argv[1], MAX_PATH, buf, NULL); 
      printf("Trying to inject (%s) on \"%s\"..\n",buf ,name);
   }
   else{
      pID = GetTargetThreadIDFromProcName(argv[2]);  
      GetFullPathName(argv[1], MAX_PATH, buf, NULL); 
      printf("Trying to inject (%s) on \"%s\"..\n",buf ,argv[2]);
   }
    
   // Inject the dll 
   if(!Inject(pID, buf))
      printf("DLL Not Loaded!"); 
    else
      printf("DLL Loaded!"); 

    _getch(); 
   return 0; 
} 

BOOL Inject(DWORD pID, const char * DLL_NAME) { 
   HANDLE Proc; 
   HMODULE hLib; 
   char buf[50] = {0}; 
   LPVOID RemoteString, LoadLibAddy; 

   if(!pID) 
      return false; 

   Proc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pID); 
   if(!Proc) { 
      sprintf(buf, "OpenProcess() failed: %d", GetLastError()); 
      printf(buf); 
      return false; 
   } 
    
   LoadLibAddy = (LPVOID)GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA"); 

   // Allocate space in the process for our DLL
   RemoteString = (LPVOID)VirtualAllocEx(Proc, NULL, strlen(DLL_NAME), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE); 

   // Write the string name of our DLL in the memory allocated
   WriteProcessMemory(Proc, (LPVOID)RemoteString, DLL_NAME, strlen(DLL_NAME), NULL); 

   // Load DLL 
   CreateRemoteThread(Proc, NULL, NULL, (LPTHREAD_START_ROUTINE)LoadLibAddy, (LPVOID)RemoteString, NULL, NULL); 

   CloseHandle(Proc); 
   return true; 
} 

DWORD GetTargetThreadIDFromProcName(const char * ProcName) { 
   PROCESSENTRY32 pe; 
   HANDLE thSnapShot; 
   BOOL retval, ProcFound = false; 

   thSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0); 
   if(thSnapShot == INVALID_HANDLE_VALUE) { 
      printf("Error: Unable to create toolhelp snapshot!"); 
      return false; 
   } 

   pe.dwSize = sizeof(PROCESSENTRY32); 
    
   retval = Process32First(thSnapShot, &pe); 
   while(retval) { 
      if(StrStrI(pe.szExeFile, ProcName))
         return pe.th32ProcessID; 
      retval = Process32Next(thSnapShot, &pe); 
   } 
   return 0; 
}