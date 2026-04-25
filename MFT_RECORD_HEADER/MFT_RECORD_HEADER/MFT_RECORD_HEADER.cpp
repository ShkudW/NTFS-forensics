#NTFS-forensics By Shkudw -> https://github.com/ShkudW/NTFS-forensics

#include <Windows.h>
#include <stdio.h>
#include <string>


#pragma pack(push, 1)
struct MFT_RECORD_HEADER {
    BYTE        Signature[4];
    WORD        UpdateSeqOffset;
    WORD        UpdateSeqCount;
    ULONGLONG   LogFileSeqNum;
    WORD        SequenceNumber;
    WORD        HardLinkCount;
    WORD        FirstAttrOffset;
    WORD        Flags;
    DWORD       UsedSize;
    DWORD       AllocatedSize;
    ULONGLONG   BaseFileRecord;
    WORD        NextAttrId;
    WORD        Padding;
    DWORD       MftRecordNumber;
};
#pragma pack(pop)


static const char* SystemRecordName(DWORD idx) {
    switch (idx) {
    case 0: return "$MFT";
    case 1: return "$MFTMirr";
    case 2: return "$LogFile";
    case 3: return "$Volume";
    case 4: return "$AttrDef";
    case 5: return ". (root directory)";
    case 6: return "$Bitmap";
    case 7: return "$Boot";
    default: return "(unknown)";
    }
}

static void PrintRecordHeader(DWORD recordIndex,
    ULONGLONG sector,
    ULONGLONG physOffset,
    const BYTE* buf)
{
    const MFT_RECORD_HEADER* h = (const MFT_RECORD_HEADER*)buf;

    printf("  Record #%-2u  |  %-20s  |  Sector: %llu\n", recordIndex, SystemRecordName(recordIndex), sector);
    printf("  struct MFT_RECORD_HEADER {\n");
    printf("    Signature        = \"FILE\"\n");
    printf("    MftRecordNumber  = %u\n", h->MftRecordNumber);
    printf("    SequenceNumber   = %u\n", h->SequenceNumber);
    printf("    HardLinkCount    = %u\n", h->HardLinkCount);
    printf("    Flags            = 0x%04X  (%s | %s)\n", h->Flags, (h->Flags & 0x01) ? "IN_USE" : "NOT_IN_USE", (h->Flags & 0x02) ? "DIRECTORY" : "FILE");
    printf("    UsedSize         = %u bytes\n", h->UsedSize);
    printf("    AllocatedSize    = %u bytes\n", h->AllocatedSize);
    printf("    BaseFileRecord   = %llu  %s\n", h->BaseFileRecord, h->BaseFileRecord == 0 ? "(base record)" : "(extension record)");
    printf("    FirstAttrOffset  = 0x%04X\n", h->FirstAttrOffset);
    printf("    LSN              = 0x%016llX\n", h->LogFileSeqNum);
    printf("  }\n");
    printf("\n");
}


int main(int argc, char* argv[])
{

    if (argc < 2) {
        printf("  Show_MFT_Records_0_7.exe <mft_start_sector>\n\n");
        return 1;
    }

    ULONGLONG mftStartSector = strtoull(argv[1], nullptr, 10);
    int       driveIdx = (argc >= 3) ? atoi(argv[2]) : 0;

    // Open physical drive

    HANDLE hDisk = CreateFileW(L"\\\\.\\PhysicalDrive0", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);

    if (hDisk == INVALID_HANDLE_VALUE) {
        return 1;
    }

    printf("[+] Sector: %llu\n", mftStartSector);

    const DWORD RECORD_SIZE = 1024;
    const DWORD RECORDS_TO_READ = 8;

    for (DWORD r = 0; r < RECORDS_TO_READ; r++) {

        ULONGLONG sector = mftStartSector + (ULONGLONG)r * 2;
        ULONGLONG physOffset = sector * 512ULL;

        // Seek
        LARGE_INTEGER li;
        li.QuadPart = (LONGLONG)physOffset;
        if (!SetFilePointerEx(hDisk, li, NULL, FILE_BEGIN)) {
            break;
        }

        // Read 1024 bytes
        BYTE  buf[RECORD_SIZE] = {};
        DWORD bytesRead = 0;
        if (!ReadFile(hDisk, buf, RECORD_SIZE, &bytesRead, NULL)
            || bytesRead != RECORD_SIZE) {
            break;
        }

        PrintRecordHeader(r, sector, physOffset, buf);
    }

    CloseHandle(hDisk);

    return 0;
}