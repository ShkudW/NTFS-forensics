#NTFS-forensics By Shkudw -> https://github.com/ShkudW/NTFS-forensics

#include <Windows.h>
#include <stdio.h>

#pragma pack(push, 1)
struct MFT_RECORD_HEADER {
    BYTE      Signature[4];
    WORD      UpdateSeqOffset;
    WORD      UpdateSeqCount;
    ULONGLONG LogFileSeqNum;
    WORD      SequenceNumber;
    WORD      HardLinkCount;
    WORD      FirstAttrOffset;
    WORD      Flags;
    DWORD     UsedSize;
    DWORD     AllocatedSize;
    ULONGLONG BaseFileRecord;
    WORD      NextAttrId;
    WORD      Padding;
    DWORD     MftRecordNumber;
};

struct ATTR_HEADER {
    DWORD  Type;
    DWORD  Length;
    BYTE   NonResident;
    BYTE   NameLength;
    WORD   NameOffset;
    WORD   Flags;
    WORD   AttrId;
};
#pragma pack(pop)

static const char* AttrTypeName(DWORD type) {
    switch (type) {
    case 0x10: return "$STANDARD_INFORMATION";
    case 0x20: return "$ATTRIBUTE_LIST";
    case 0x30: return "$FILE_NAME";
    case 0x40: return "$OBJECT_ID";
    case 0x50: return "$SECURITY_DESCRIPTOR";
    case 0x60: return "$VOLUME_NAME";
    case 0x70: return "$VOLUME_INFORMATION";
    case 0x80: return "$DATA";
    case 0x90: return "$INDEX_ROOT";
    case 0xA0: return "$INDEX_ALLOCATION";
    case 0xB0: return "$BITMAP";
    case 0xC0: return "$REPARSE_POINT";
    case 0xFFFFFFFF: return "END";
    default:         return "UNKNOWN";
    }
}

int main(int argc, char* argv[])
{

    if (argc < 2) {
        printf("  Show_Attr_Walk.exe <sector> [driveIndex]\n\n");
        return 1;
    }

    ULONGLONG sector = strtoull(argv[1], nullptr, 10);
    int       driveIdx = (argc >= 3) ? atoi(argv[2]) : 0;


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
    if (buf[0] != 'F' || buf[1] != 'I' || buf[2] != 'L' || buf[3] != 'E') {
        printf("[!] Not a valid MFT record.\n"); return 1;
    }

    MFT_RECORD_HEADER* hdr = (MFT_RECORD_HEADER*)buf;

    printf("\n");
    printf("[+] Sector          : %llu\n", sector);
    printf("[+] MFT Record #    : %u\n", hdr->MftRecordNumber);
    printf("[+] FirstAttrOffset : 0x%04X\n\n", hdr->FirstAttrOffset);

    printf("  Walking Attributes from offset 0x%04X:\n\n", hdr->FirstAttrOffset);

    DWORD offset = hdr->FirstAttrOffset;
    int   step = 0;

    while (offset + sizeof(ATTR_HEADER) <= hdr->UsedSize) {
        ATTR_HEADER* a = (ATTR_HEADER*)(buf + offset);
        if (a->Type == 0xFFFFFFFF) break;
        if (a->Length == 0 || offset + a->Length > 1024) break;

        const char* res = a->NonResident ? "Non-Resident" : "Resident";

        printf("[+] Step % d\n", step + 1);
        printf("    [#] Offset      : 0x%04X    \n", offset);
        printf("    [#] Type        : 0x%08X    \n", a->Type);
        printf("    [#] Name        : %-22s \n", AttrTypeName(a->Type));
        printf("    [#] Length      : %u bytes| \n", a->Length);
        printf("    [#] NonResident : %s    \n", a->NonResident ? "1  (Non-Resident)" : "0  (Resident)    ");
        printf("\n");

        DWORD next = offset + a->Length;


        offset = next;
        step++;
    }

    return 0;
}