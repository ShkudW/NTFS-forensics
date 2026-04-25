#NTFS-forensics By Shkudw -> https://github.com/ShkudW/NTFS-forensics

#include <windows.h>
#include <iostream>
#include <iomanip>

#pragma pack(push, 1)
typedef struct {
    BYTE  PartitionTypeGUID[16];
    BYTE  UniquePartitionGUID[16];
    unsigned __int64 StartingLBA;
    unsigned __int64 EndingLBA;
    unsigned __int64 Attributes;
    WCHAR PartitionName[36];
} GPT_PARTITION_ENTRY;
#pragma pack(pop)


void PrintHex(const BYTE* data, size_t size) {
    for (size_t i = 0; i < size; i++) {
        std::cout << std::setfill('0') << std::setw(2) << std::hex << (int)data[i] << " ";
        if ((i + 1) % 16 == 0) std::cout << std::endl;
    }
}

int main() {

    HANDLE hDisk = CreateFileW(L"\\\\.\\PhysicalDrive0", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);

    if (hDisk == INVALID_HANDLE_VALUE) {
        return 1;
    }

    LARGE_INTEGER offset;
    offset.QuadPart = 2 * 512;

    if (!SetFilePointerEx(hDisk, offset, NULL, FILE_BEGIN)) {
        CloseHandle(hDisk);
        return 1;
    }

    BYTE buffer[512];
    DWORD bytesRead;

    if (ReadFile(hDisk, buffer, 512, &bytesRead, NULL)) {
        std::cout << "[+] Sector 2 :" << std::endl;
        std::cout << "\n" << std::endl;
        PrintHex(buffer, 512);
        std::cout << "\n" << std::endl;

        GPT_PARTITION_ENTRY* entries = (GPT_PARTITION_ENTRY*)buffer;


        for (int i = 0; i < 4; i++) {
            if (entries[i].PartitionTypeGUID[0] != 0 || entries[i].PartitionTypeGUID[15] != 0) {

                std::wcout << std::left << std::setw(30) << entries[i].PartitionName;
                std::cout << std::left << std::setw(15) << std::dec << entries[i].StartingLBA << "0x" << std::hex << (entries[i].StartingLBA * 512) << std::endl;
                std::cout << "\n" << std::endl;
            }
        }
    }

    CloseHandle(hDisk);
    return 0;
}