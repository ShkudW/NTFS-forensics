#NTFS-forensics By Shkudw -> https://github.com/ShkudW/NTFS-forensics

#include <windows.h>
#include <iostream>
#include <iomanip>
#include <string>


void PrintHexDump(const BYTE* data, size_t size) {
    for (size_t i = 0; i < size; i += 16) {
        std::cout << std::setfill('0') << std::setw(4) << std::hex << i << "  ";
        for (size_t j = 0; j < 16; ++j) {
            if (i + j < size)
                std::cout << std::setw(2) << (int)data[i + j] << " ";
            else
                std::cout << "   ";
        }
        std::cout << " |";
        for (size_t j = 0; j < 16; ++j) {
            if (i + j < size) {
                BYTE c = data[i + j];
                std::cout << (c >= 32 && c <= 126 ? (char)c : '.');
            }
        }
        std::cout << "|" << std::endl;
    }
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cout << "Usage: " << argv[0] << " <Sector_Number>" << std::endl;
        return 1;
    }

    unsigned long long sectorNumber = std::stoull(argv[1]);

    HANDLE hDisk = CreateFileW(L"\\\\.\\PhysicalDrive0", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);

    if (hDisk == INVALID_HANDLE_VALUE) {
        return 1;
    }

    LARGE_INTEGER offset;
    offset.QuadPart = sectorNumber * 512;

    if (!SetFilePointerEx(hDisk, offset, NULL, FILE_BEGIN)) {
        CloseHandle(hDisk);
        return 1;
    }

    BYTE buffer[512] = { 0 };
    DWORD bytesRead = 0;

    if (ReadFile(hDisk, buffer, 512, &bytesRead, NULL)) {
        std::cout << "\n[+] Sector:" << std::dec << sectorNumber << std::endl;
        std::cout << "\n" << std::endl;
        PrintHexDump(buffer, 512);
        std::cout << "\n" << std::endl;
    }
    else {
        std::cerr << "[-] ReadFile failed. Error: " << GetLastError() << std::endl;
    }

    CloseHandle(hDisk);
    return 0;
}