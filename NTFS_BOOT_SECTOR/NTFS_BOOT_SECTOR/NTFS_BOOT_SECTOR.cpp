#NTFS-forensics By Shkudw -> https://github.com/ShkudW/NTFS-forensics

#include <windows.h>
#include <iostream>
#include <iomanip>
#include <string>

#pragma pack(push, 1)
typedef struct {
    BYTE  JumpInstruction[3];
    BYTE  OemID[8];
    WORD  BytesPerSector;
    BYTE  SectorsPerCluster;
    WORD  ReservedSectors;
    BYTE  Fats;
    WORD  RootEntries;
    WORD  SmallSectors;
    BYTE  MediaDescriptor;
    WORD  SectorsPerFat;
    WORD  SectorsPerTrack;
    WORD  HeadsPerCylinder;
    DWORD HiddenSectors;
    DWORD LargeSectors;
    BYTE  PhysicalDiskNumber;
    BYTE  CurrentHead;
    BYTE  ExtendedBootSignature;
    BYTE  Reserved1;
    ULONGLONG TotalSectors;
    ULONGLONG MftLcn;
    ULONGLONG MftMirrLcn;
    CHAR  ClustersPerMftRecord;
    BYTE  Reserved2[3];
    CHAR  ClustersPerIndexBuffer;
    BYTE  Reserved3[3];
    ULONGLONG VolumeSerialNumber;
    DWORD Checksum;
    BYTE  BootCode[426];
    WORD  BootSignature;
} NTFS_BOOT_SECTOR;
#pragma pack(pop)

void DisplayFullVBR(const NTFS_BOOT_SECTOR* vbr, unsigned long long startSector) {

    std::string oemId((char*)vbr->OemID, 8);
    std::cout << "\n" << std::endl;
    std::cout << std::left << std::setw(30) << "OEM ID:" << oemId << std::endl;
    std::cout << std::left << std::setw(30) << "Bytes Per Sector:" << std::dec << vbr->BytesPerSector << std::endl;
    std::cout << std::left << std::setw(30) << "Sectors Per Cluster:" << (int)vbr->SectorsPerCluster << std::endl;
    std::cout << std::left << std::setw(30) << "Media Descriptor:" << "0x" << std::hex << (int)vbr->MediaDescriptor << std::endl;
    std::cout << std::left << std::setw(30) << "Total Sectors:" << std::dec << vbr->TotalSectors << std::endl;
    double sizeGB = (double)vbr->TotalSectors * vbr->BytesPerSector / (1024.0 * 1024.0 * 1024.0);
    std::cout << std::left << std::setw(30) << "Volume Size:" << std::fixed << std::setprecision(2) << sizeGB << " GB" << std::endl;
    std::cout << "------------------------------------------------------------" << std::endl;
    std::cout << std::left << std::setw(30) << "$MFT Start Cluster (LCN):" << "0x" << std::hex << vbr->MftLcn << " (" << std::dec << vbr->MftLcn << ")" << std::endl;

    int recordSize = (vbr->ClustersPerMftRecord < 0) ? (1 << (-vbr->ClustersPerMftRecord)) : (vbr->ClustersPerMftRecord * vbr->SectorsPerCluster * vbr->BytesPerSector);
    std::cout << std::left << std::setw(30) << "MFT Record Size:" << std::dec << recordSize << " bytes" << std::endl;
    std::cout << "\n" << std::endl;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cout << "Usage: " << argv[0] << " <Starting_Sector>" << std::endl;
        return 1;
    }

    unsigned long long startSector = std::stoull(argv[1]);
    HANDLE hDisk = CreateFileW(L"\\\\.\\PhysicalDrive0", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);

    if (hDisk == INVALID_HANDLE_VALUE) return 1;

    LARGE_INTEGER offset;
    offset.QuadPart = startSector * 512;
    SetFilePointerEx(hDisk, offset, NULL, FILE_BEGIN);

    BYTE buffer[512];
    DWORD bytesRead;
    if (ReadFile(hDisk, buffer, 512, &bytesRead, NULL)) {
        DisplayFullVBR((NTFS_BOOT_SECTOR*)buffer, startSector);
    }

    CloseHandle(hDisk);
    return 0;
}