#NTFS-forensics By Shkudw -> https://github.com/ShkudW/NTFS-forensics

#include <Windows.h>
#include <stdio.h>

#pragma pack(push, 1)

struct ATTR_HEADER {
    DWORD  Type;
    DWORD  Length;
    BYTE   NonResident;
    BYTE   NameLength;
    WORD   NameOffset;
    WORD   Flags;
    WORD   AttrId;
};

struct ATTR_NONRESIDENT_EXT {
    ULONGLONG StartVCN;
    ULONGLONG EndVCN;
    WORD      DataRunsOffset;
    WORD      CompressionUnit;
    DWORD     Padding;
    ULONGLONG AllocatedSize;
    ULONGLONG DataSize;
    ULONGLONG InitializedSize;
};

#pragma pack(pop)

static int CountDataRunBytes(const BYTE* ptr) {
    const BYTE* start = ptr;
    while (*ptr != 0x00) {
        BYTE h = *ptr++;
        BYTE lb = h & 0x0F;
        BYTE ob = (h >> 4) & 0x0F;
        if (lb == 0) break;
        ptr += lb + ob;
    }
    return (int)(ptr - start) + 1;
}

int main(int argc, char* argv[])
{


    if (argc < 3) {
        printf("  Show_DataRuns_HEX.exe <sector> <attr_offset_hex> [driveIndex]\n\n");
        return 1;
    }

    ULONGLONG sector = strtoull(argv[1], nullptr, 10);
    DWORD     attrOffset = (DWORD)strtoul(argv[2], nullptr, 16);
    int       driveIdx = (argc >= 4) ? atoi(argv[3]) : 0;


    HANDLE hDisk = CreateFileW(L"\\\\.\\PhysicalDrive0", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);

    if (hDisk == INVALID_HANDLE_VALUE) {
        return 1;
    }

    LARGE_INTEGER li;
    li.QuadPart = (LONGLONG)(sector * 512ULL);
    SetFilePointerEx(hDisk, li, NULL, FILE_BEGIN);

    BYTE  buf[1024] = {};
    DWORD bytesRead = 0;
    ReadFile(hDisk, buf, 1024, &bytesRead, NULL);
    CloseHandle(hDisk);

    if (bytesRead != 1024) { printf("[!] Read failed.\n"); return 1; }


    ATTR_HEADER* a = (ATTR_HEADER*)(buf + attrOffset);

    if (a->NonResident != 1) {
        printf("[!] Attribute at 0x%04X is Resident -- no Data Runs.\n", attrOffset);
        return 1;
    }


    ATTR_NONRESIDENT_EXT* nr =
        (ATTR_NONRESIDENT_EXT*)(buf + attrOffset + sizeof(ATTR_HEADER));

    DWORD runsAbsOffset = attrOffset + nr->DataRunsOffset;
    const BYTE* runs = buf + runsAbsOffset;
    int   runBytes = CountDataRunBytes(runs);

    printf("\n");
    printf("[+] Sector              : %llu\n", sector);
    printf("[+] $DATA attr offset   : 0x%04X\n", attrOffset);
    printf("[+] DataRunsOffset      : 0x%04X  (relative to attribute start)\n",
        nr->DataRunsOffset);
    printf("[+] Data Runs abs offset: 0x%04X  (within the record)\n", runsAbsOffset);
    printf("[+] Data Size           : %llu bytes\n", nr->DataSize);
    printf("[+] VCN range           : %llu -> %llu\n\n",
        nr->StartVCN, nr->EndVCN);

    printf("  Raw Data Runs bytes (%d bytes):\n\n", runBytes);

    for (int i = 0; i < runBytes; i++) {
        if (i % 16 == 0)
            printf("  %04X  ", runsAbsOffset + i);

        printf("%02X ", runs[i]);

        if ((i + 1) % 16 == 0)
            printf("\n");
    }
    if (runBytes % 16 != 0) printf("\n\n");


    return 0;
}