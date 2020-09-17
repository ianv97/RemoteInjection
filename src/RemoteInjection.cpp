#include <stdio.h>
#include <windows.h>
#include <iostream>

int main(int argc, char **argv)
{
    // Obtenemos el handle al proceso objetivo
    int processId;
    printf("Id del proceso objetivo: ");
    scanf_s("%d", &processId);
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
    if (hProcess == NULL || hProcess == INVALID_HANDLE_VALUE) {
        printf("Couldn't open target process\n");
        return -1;
    }

    // Asignamos memoria en el proceso objetivo
    PVOID remoteMemory = VirtualAllocEx(hProcess, NULL, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    printf("Remote memory: %p\n", remoteMemory);

    // Escribimos el nombre de la dll que queremos que el proceso objetivo cargue
    char dllPath[255];
    printf("Path de la dll a inyectar: ");
    scanf_s("%s", dllPath, sizeof(dllPath));
    SIZE_T bytesWritten = 0;
    WriteProcessMemory(hProcess, remoteMemory, dllPath, sizeof(dllPath), &bytesWritten);

    // Creamos un thread que invoca loadlibrary en el proceso destino
    DWORD thread_id = 0;
    CreateRemoteThread(hProcess, NULL, NULL, (LPTHREAD_START_ROUTINE) LoadLibraryA, remoteMemory, 0, &thread_id);
}
