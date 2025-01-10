#include <windows.h>
#include <iostream>

HHOOK hHook;

// Hook procedure to capture and block the keypress
LRESULT CALLBACK LowLevelKeyboardProc(int nCode, WPARAM wParam, LPARAM lParam) {
    if (nCode == HC_ACTION) {
        KBDLLHOOKSTRUCT* pKeyboard = (KBDLLHOOKSTRUCT*)lParam;

        if (wParam == WM_KEYDOWN || wParam == WM_SYSKEYDOWN) {
            std::cout << (char)pKeyboard->vkCode;
            if (pKeyboard->vkCode == 0x41) {  // 'A' key
                std::cout << "'A' key detected and blocked!" << std::endl;

                // Return 1 to block the key completely and stop it from being processed
                return 1;
            }
        }
        // Handle the key up event as well (optional)
        if (wParam == WM_KEYUP || wParam == WM_SYSKEYUP) {
            if (pKeyboard->vkCode == 0x41) {  // 'A' key
                std::cout << "'A' key release detected and blocked!" << std::endl;

                // Block the key up event as well
                return 1;
            }
        }
    }

    // Pass to the next hook in the chain
    return CallNextHookEx(hHook, nCode, wParam, lParam);
}

int main() {
    // Install the hook
    hHook = SetWindowsHookEx(WH_KEYBOARD_LL, LowLevelKeyboardProc, NULL, 0);
    if (hHook == NULL) {
        std::cerr << "Failed to install hook!" << std::endl;
        return 1;
    }

    std::cout << "Hook installed. Press 'A' to block it..." << std::endl;

    // Keep the hook active
    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    // Uninstall the hook before exiting
    UnhookWindowsHookEx(hHook);

    return 0;
}
