#include <windows.h>
#include <iostream>
#include <string>

HHOOK g_hHook = NULL;
std::wstring g_password;
bool g_passwordEntered = false;


bool StartDriver(const std::wstring& serviceName) {
    SC_HANDLE hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
    if (!hSCManager) {
        std::wcerr << L"Failed to open Service Manager. Error: " << GetLastError() << std::endl;
        return false;
    }

    SC_HANDLE hService = OpenService(hSCManager, serviceName.c_str(), SERVICE_START);
    if (!hService) {
        std::wcerr << L"Failed to open service: " << serviceName << L". Error: " << GetLastError() << std::endl;
        CloseServiceHandle(hSCManager);
        return false;
    }

    if (!StartService(hService, 0, NULL)) {
        std::wcerr << L"Failed to start service: " << serviceName << L". Error: " << GetLastError() << std::endl;
        CloseServiceHandle(hService);
        CloseServiceHandle(hSCManager);
        return false;
    }

    std::wcout << L"Service started successfully: " << serviceName << std::endl;

    CloseServiceHandle(hService);
    CloseServiceHandle(hSCManager);
    return true;
}

bool StopDriver(const std::wstring& serviceName) {
    SC_HANDLE hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
    if (!hSCManager) {
        std::wcerr << L"Failed to open Service Manager. Error: " << GetLastError() << std::endl;
        return false;
    }

    SC_HANDLE hService = OpenService(hSCManager, serviceName.c_str(), SERVICE_STOP | SERVICE_QUERY_STATUS);
    if (!hService) {
        std::wcerr << L"Failed to open service: " << serviceName << L". Error: " << GetLastError() << std::endl;
        CloseServiceHandle(hSCManager);
        return false;
    }

    SERVICE_STATUS serviceStatus;
    if (!ControlService(hService, SERVICE_CONTROL_STOP, &serviceStatus)) {
        std::wcerr << L"Failed to stop service: " << serviceName << L". Error: " << GetLastError() << std::endl;
        CloseServiceHandle(hService);
        CloseServiceHandle(hSCManager);
        return false;
    }

    std::wcout << L"Service stopped successfully: " << serviceName << std::endl;

    CloseServiceHandle(hService);
    CloseServiceHandle(hSCManager);
    return true;
}

LRESULT CALLBACK PasswordHookProc(int nCode, WPARAM wParam, LPARAM lParam) {
    if (wParam == WM_KEYUP || wParam == WM_SYSKEYUP) {
        return 1;
    }
    if (nCode == HC_ACTION && wParam == WM_KEYDOWN) {
        KBDLLHOOKSTRUCT* pKbd = (KBDLLHOOKSTRUCT*)lParam;
        wchar_t buffer[255] = { 0 };
        BYTE keyboardState[256];

        // Get the keyboard state
        GetKeyboardState(keyboardState);

        // Translate virtual key to character
        if (ToUnicode(pKbd->vkCode, pKbd->scanCode, keyboardState, buffer, 4, 0) > 0) {
            // Append the character to the password if it's not Enter
            if (pKbd->vkCode == VK_RETURN) {
                g_passwordEntered = true; // Password entry complete
            }
            else {
                g_password += buffer;
                return 1;
            }
        }
    }

    return CallNextHookEx(g_hHook, nCode, wParam, lParam);
}

int main() {
    std::wcout << L"Enter service name";
    std::wstring serviceName = L"Mydeath33";
    std::wcin >> serviceName;
    std::wcout << L"Enter command (start, stop, exit): ";
    std::wcout << L"Type 'password' or * to start entering your password.\n";

    while (true) {
        std::wstring command;
        std::wcin >> command;

        if (command == L"password" or command == L"*") {
            // Step 1: Install the password hook
            g_hHook = SetWindowsHookEx(WH_KEYBOARD_LL, PasswordHookProc, NULL, 0);
            if (!g_hHook) {
                std::wcerr << L"Failed to install hook.\n";
                continue;
            }

            // Step 2: Start the driver
            if (!StartDriver(serviceName)) {
                std::wcerr << L"Failed to start the driver.\n";
                UnhookWindowsHookEx(g_hHook);
                continue;
            }

            std::wcout << L"Enter your password (press Enter when done):\n";

            // Step 3: Wait for password entry
            MSG msg;
            while (!g_passwordEntered) {
                while (PeekMessage(&msg, NULL, 0, 0, PM_REMOVE)) {
                    TranslateMessage(&msg);
                    DispatchMessage(&msg);
                }
            }

            // Step 4: Stop the driver
            StopDriver(serviceName);

            // Step 5: Remove the hook
            UnhookWindowsHookEx(g_hHook);
            g_hHook = NULL;

            // Step 6: Print the captured password
            std::wcout << L"Password entered: " << g_password << L"\n";

            // Reset for the next password entry
            g_password.clear();
            g_passwordEntered = false;
        }
        else if (command == L"exit") {
            break;
        }
        else if (command == L"start") {
            if (!StartDriver(serviceName)) {
                std::wcerr << L"Failed to start the driver." << std::endl;
            }
        }
        else if (command == L"stop") {
            if (!StopDriver(serviceName)) {
                std::wcerr << L"Failed to stop the driver." << std::endl;
            }
        }
        else {
            std::wcout << L"Unknown command. " << command << L" Type 'password or *' to start or 'exit' to quit.\n";
        }
    }

    return 0;
}

