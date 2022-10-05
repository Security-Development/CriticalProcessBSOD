#include <stdio.h>
#include <windows.h>

typedef long (WINAPI *NewRtlSetProcessIsCritical) (
    BOOLEAN bNew,
    BOOLEAN *pbOld,
    BOOLEAN bNeedScb
);

BOOLEAN levelup_privileges(HANDLE handle)
{
   HANDLE hProc = NULL;
   HANDLE hToken = NULL;
   LUID luid;
   TOKEN_PRIVILEGES tp;
   
   if (OpenProcessToken(handle, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
   {
   
         if (LookupPrivilegeValue(NULL, "SeDebugPrivilege", &luid)) 
   
         {  
   
            tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
   
             tp.Privileges[0].Luid = luid;
   
             tp.PrivilegeCount = 1;  
   
             AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL); 
   
             return TRUE; 
   
       } 

}

 return FALSE;

 }
 
int main() {
   printf("[*] Getting debug permission...\n");
   levelup_privileges(GetCurrentProcess());
   printf("[+] Debug permission has been obtained\n");
   
   HMODULE ntdll = GetModuleHandleA("ntdll.dll");
   NewRtlSetProcessIsCritical func  = GetProcAddress(ntdll, "RtlSetProcessIsCritical");
   if( func == 0x00000000 )
   {
      printf("[-] Not Found Function")
   } else {
      printf("[+] RtlSetProcessIsCritical Address : 0x%08x", func);
      func(TRUE, NULL, FALSE);
   }
   
   return 0;
}
