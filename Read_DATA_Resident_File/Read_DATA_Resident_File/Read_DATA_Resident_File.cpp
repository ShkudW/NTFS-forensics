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

struct ATTR_RESIDENT_EXT {
    DWORD  ValueLength;
    WORD   ValueOffset; 
    BYTE   IndexedFlag;
    BYTE   Padding;
};

#pragma pack(pop)

int main(int argc, char* argv[])
{


    if (argc < 3) {
        printf("  Read_Resident_Data.exe <sector> <attr_offset_hex> [driveIndex]\n\n");
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

    // ---- Validate attribute ----
    ATTR_HEADER* a = (ATTR_HEADER*)(buf + attrOffset);
    ATTR_RESIDENT_EXT* r = (ATTR_RESIDENT_EXT*)(buf + attrOffset + sizeof(ATTR_HEADER));

    if (a->Type != 0x80) {
        printf("[!] Attribute at 0x%04X is not $DATA (Type = 0x%08X)\n",
            attrOffset, a->Type);
        return 1;
    }
    if (a->NonResident) {
        printf("[!] $DATA is Non-Resident -- use Show_DataRuns_HEX instead.\n");
        return 1;
    }

    DWORD      valueOffset = attrOffset + r->ValueOffset;
    DWORD      valueLength = r->ValueLength;
    const BYTE* value = buf + valueOffset;

    printf("\n");
    printf("[+] Sector             : %llu\n", sector);
    printf("[+] $DATA attr offset  : 0x%04X\n", attrOffset);
    printf("[+] Value offset       : 0x%04X  (attr + 0x%02X)\n",
        valueOffset, r->ValueOffset);
    printf("[+] Value length       : %u bytes\n\n", valueLength);

    if (valueLength == 0) {
        printf("  (empty file -- no content)\n");
    }
    else {

        for (DWORD i = 0; i < valueLength; i += 16) {
            printf("  %04X     ", valueOffset + i);

            // HEX
            for (DWORD j = 0; j < 16; j++) {
                if (i + j < valueLength)
                    printf("%02X ", value[i + j]);
                else
                    printf("   ");
            }

            printf(" ");

            // ASCII
            for (DWORD j = 0; j < 16 && i + j < valueLength; j++) {
                BYTE b = value[i + j];
                printf("%c", (b >= 0x20 && b < 0x7F) ? b : '.');
            }
            printf("\n\n");
        }
    }


    return 0;
}