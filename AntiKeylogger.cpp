#include <ntddk.h>
#include <ntimage.h>

NTSTATUS ReadFileContent(PCUNICODE_STRING FilePath, PVOID* FileBuffer, PULONG FileSize) {
    HANDLE fileHandle;
    OBJECT_ATTRIBUTES objAttributes;
    IO_STATUS_BLOCK ioStatusBlock;
    NTSTATUS status;
    PVOID buffer = NULL;
    ULONG fileLength = 0;

    InitializeObjectAttributes(&objAttributes, (PUNICODE_STRING)FilePath, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

    // Open the file
    status = ZwCreateFile(
        &fileHandle,
        GENERIC_READ,
        &objAttributes,
        &ioStatusBlock,
        NULL,
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ,
        FILE_OPEN,
        FILE_SYNCHRONOUS_IO_NONALERT,
        NULL,
        0
    );

    if (!NT_SUCCESS(status)) {
        KdPrint(("[AntiKeylogger] Failed to open file: 0x%x\n", status));
        return status;
    }

    // Query file size
    FILE_STANDARD_INFORMATION fileInfo;
    status = ZwQueryInformationFile(fileHandle, &ioStatusBlock, &fileInfo, sizeof(fileInfo), FileStandardInformation);

    if (!NT_SUCCESS(status)) {
        KdPrint(("[AntiKeylogger] Failed to query file info: 0x%x\n", status));
        ZwClose(fileHandle);
        return status;
    }

    fileLength = (ULONG)fileInfo.EndOfFile.QuadPart;

    // Allocate buffer
    buffer = ExAllocatePool2(POOL_FLAG_NON_PAGED, fileLength, 'File');
    if (!buffer) {
        KdPrint(("[AntiKeylogger] Memory allocation failed.\n"));
        ZwClose(fileHandle);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    // Read the file content
    status = ZwReadFile(fileHandle, NULL, NULL, NULL, &ioStatusBlock, buffer, fileLength, NULL, NULL);
    if (!NT_SUCCESS(status)) {
        KdPrint(("[AntiKeylogger] Failed to read file: 0x%x\n", status));
        ExFreePool(buffer);
        ZwClose(fileHandle);
        return status;
    }

    // Close file handle
    ZwClose(fileHandle);

    *FileBuffer = buffer;
    *FileSize = fileLength;

    return STATUS_SUCCESS;
}

BOOLEAN ContainsSubstring(PVOID buffer, ULONG bufferSize, const CHAR* substring) {
    ULONG substringLength = (ULONG)strlen(substring);

    if (bufferSize < substringLength) {
        return FALSE;
    }

    for (ULONG i = 0; i <= bufferSize - substringLength; i++) {
        if (memcmp((PUCHAR)buffer + i, substring, substringLength) == 0) {
            return TRUE;
        }
    }

    return FALSE;
}

void AnalyzeExecutable(PUNICODE_STRING CommandLine) {
    PVOID fileBuffer = NULL;
    ULONG fileSize = 0;
    NTSTATUS status;

    if (!CommandLine || !CommandLine->Buffer) {
        KdPrint(("[AntiKeylogger] Invalid CommandLine parameter.\n"));
        return;
    }

    KdPrint(("[AntiKeylogger] Analyzing executable: %wZ\n", CommandLine));

    status = ReadFileContent(CommandLine, &fileBuffer, &fileSize);
    if (NT_SUCCESS(status)) {
        KdPrint(("[AntiKeylogger] File content loaded (%lu bytes).\n", fileSize));

        // Search for the string "SetWindowsHookEx"
        const CHAR* targetString = "SetWindowsHookEx";
        if (ContainsSubstring(fileBuffer, fileSize, targetString)) {
            KdPrint(("[AntiKeylogger] Potential keylogger detected! Found \"%s\" in the executable.\n", targetString));
        }
        else {
            KdPrint(("[AntiKeylogger] No suspicious activity detected in the executable.\n"));
        }

        // Clean up the allocated buffer
        ExFreePool(fileBuffer);
    }
    else {
        KdPrint(("[AntiKeylogger] Failed to read executable file.\n"));
    }
}


void ProcessNotifyRoutineEx(
    PEPROCESS Process,
    HANDLE ProcessId,
    PPS_CREATE_NOTIFY_INFO CreateInfo
) {
    UNREFERENCED_PARAMETER(Process);

    if (CreateInfo) {
        DbgPrintEx(
            DPFLTR_IHVDRIVER_ID,
            DPFLTR_ERROR_LEVEL,
            "[*] PID: %d  ***  ParentPID: %d  ***  ImageName: %wZ  ***  CmdLine: %wZ \r\n",
            ProcessId,
            CreateInfo->ParentProcessId,
            CreateInfo->ImageFileName,
            CreateInfo->CommandLine
        );

        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[AntiKeylogger] New process detected.\n");

        // Check if the process path starts with "C:\Windows"
        if (CreateInfo->ImageFileName && CreateInfo->ImageFileName->Buffer) {
            UNICODE_STRING windowsPath;
            RtlInitUnicodeString(&windowsPath, L"\\??\\C:\\Windows");

            if (RtlPrefixUnicodeString(&windowsPath, CreateInfo->ImageFileName, TRUE)) {
                DbgPrintEx(
                    DPFLTR_IHVDRIVER_ID,
                    DPFLTR_INFO_LEVEL,
                    "[AntiKeylogger] Skipping process from C:\\Windows: %wZ\n",
                    CreateInfo->ImageFileName
                );
                return;
            }
        }

        // Analyze the executable
        AnalyzeExecutable((PUNICODE_STRING)CreateInfo->ImageFileName);

        // Search for the string "SetWindowsHookEx"
        PVOID fileBuffer = NULL;
        ULONG fileSize = 0;
        NTSTATUS status = ReadFileContent(CreateInfo->ImageFileName, &fileBuffer, &fileSize);

        if (NT_SUCCESS(status) && fileBuffer) {
            const CHAR* targetString = "SetWindowsHookEx";
            if (ContainsSubstring(fileBuffer, fileSize, targetString)) {
                DbgPrintEx(
                    DPFLTR_IHVDRIVER_ID,
                    DPFLTR_WARNING_LEVEL,
                    "[AntiKeylogger] Terminating suspicious process PID: %d\n",
                    ProcessId
                );

                // Terminate the process
                HANDLE processHandle = NULL;
                CLIENT_ID clientId;
                OBJECT_ATTRIBUTES objAttributes;

                clientId.UniqueProcess = ProcessId;
                clientId.UniqueThread = NULL;

                InitializeObjectAttributes(&objAttributes, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);

                status = ZwOpenProcess(&processHandle, STANDARD_RIGHTS_REQUIRED | 0x1, &objAttributes, &clientId);
                if (NT_SUCCESS(status)) {
                    ZwTerminateProcess(processHandle, STATUS_SUCCESS);
                    ZwClose(processHandle);
                }
                else {
                    DbgPrintEx(
                        DPFLTR_IHVDRIVER_ID,
                        DPFLTR_ERROR_LEVEL,
                        "[AntiKeylogger] Failed to open or terminate process PID: %d, Status: 0x%x\n",
                        ProcessId,
                        status
                    );
                }
            }
            ExFreePool(fileBuffer);
        }
    }
    else {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[*] Process %d has ended\n", ProcessId);
    }
}

void DriverUnload(PDRIVER_OBJECT DriverObject) {
    KdPrint(("Sample driver DriverUnload\n"));
    UNREFERENCED_PARAMETER(DriverObject);
    PsSetCreateProcessNotifyRoutineEx(ProcessNotifyRoutineEx, TRUE);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[AntiKeylogger] Driver unloaded.\n");
}

extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    KdPrint(("Sample driver DriverEntry\n"));
    UNREFERENCED_PARAMETER(RegistryPath);
    DriverObject->DriverUnload = DriverUnload;
    PsSetCreateProcessNotifyRoutineEx(ProcessNotifyRoutineEx, FALSE);
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[AntiKeylogger] Driver loaded.\n");
    return STATUS_SUCCESS;
}
