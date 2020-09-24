#include <stdio.h>
#include <windows.h>
#include <iostream>

int main()
{
    int method;
    printf("Select DLL Injection (1=CreateRemoteThread, 2=SetWindowsHooxEx): ");
    scanf_s("%d", &method);

    char dllPath[255];
    printf("Path de la dll a inyectar: ");
    scanf_s("%s", dllPath, sizeof(dllPath));

    // --------------------------------- CREATE REMOTE THREAD -----------------------------------------------------
    if (method == 1) {
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
}
