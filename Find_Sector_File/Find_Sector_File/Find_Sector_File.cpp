#NTFS-forensics By Shkudw -> https://github.com/ShkudW/NTFS-forensics

#include <Windows.h>
#include <stdio.h>
#include <string>
#include <algorithm>


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

struct ATTR_RESIDENT_EXT {
    DWORD  ValueLength;
    WORD   ValueOffset;
    BYTE   IndexedFlag;
    BYTE   Padding;
};

struct FILE_NAME_ATTR {
    ULONGLONG ParentDirectory;
    ULONGLONG CreationTime;
    ULONGLONG ModifiedTime;
    ULONGLONG MFTChangedTime;
    ULONGLONG AccessTime;
    ULONGLONG AllocatedSize;
    ULONGLONG DataSize;
    DWORD     FileAttributes;
    DWORD     EaOrReparseTag;
    BYTE      FileNameLength;
    BYTE      Namespace;
    WCHAR     FileName[1];
};

#pragma pack(pop)

static std::string FiletimeToStr(ULONGLONG ft) {
    if (ft == 0) return "(not set)";
    FILETIME f;
    f.dwLowDateTime = (DWORD)(ft & 0xFFFFFFFF);
    f.dwHighDateTime = (DWORD)(ft >> 32);
    SYSTEMTIME s = {};
    FileTimeToSystemTime(&f, &s);
    char buf[32];
    sprintf_s(buf, "%04d-%02d-%02d  %02d:%02d:%02d",
        s.wYear, s.wMonth, s.wDay,
        s.wHour, s.wMinute, s.wSecond);
    return buf;
}


static bool StrEqNoCase(const std::string& a, const std::string& b) {
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); i++)
        if (tolower((unsigned char)a[i]) != tolower((unsigned char)b[i]))
            return false;
    return true;
}

static void PrintMatch(ULONGLONG sector, const MFT_RECORD_HEADER* hdr,
    const FILE_NAME_ATTR* fn, const char* name)
{
    printf("\n");;
    printf("[!!] FOUND: \"%s\"\n", name);
    printf("\n\n");

    printf("  MFT Record #     : %u\n", hdr->MftRecordNumber);
    printf("  Sector           : %llu\n", sector);

    printf("  Type             : ");
    if (hdr->Flags & 0x02)
        printf("Directory\n");
    else
        printf("File\n");

    printf("  Status           : %s\n", (hdr->Flags & 0x01) ? "IN_USE" : "DELETED");
    printf("  Hard Links       : %u\n", hdr->HardLinkCount);
    printf("  Parent Record #  : %llu\n", fn->ParentDirectory & 0x0000FFFFFFFFFFFFULL);

    printf("  Data Size        : %llu bytes\n", fn->DataSize);
    printf("  Created          : %s\n", FiletimeToStr(fn->CreationTime).c_str());
    printf("  Modified         : %s\n", FiletimeToStr(fn->ModifiedTime).c_str());
    printf("  Accessed         : %s\n", FiletimeToStr(fn->AccessTime).c_str());

    printf("\n");
}


static bool ScanRecord(const BYTE* buf, ULONGLONG sector,
    const std::string& target)
{
    // Validate "FILE" signature
    if (buf[0] != 'F' || buf[1] != 'I' || buf[2] != 'L' || buf[3] != 'E')
        return false;

    const MFT_RECORD_HEADER* hdr = (const MFT_RECORD_HEADER*)buf;

    DWORD offset = hdr->FirstAttrOffset;

    while (offset + sizeof(ATTR_HEADER) <= hdr->UsedSize) {
        const ATTR_HEADER* a = (const ATTR_HEADER*)(buf + offset);

        if (a->Type == 0xFFFFFFFF) break;
        if (a->Length == 0 || offset + a->Length > 1024) break;

        if (a->Type == 0x30 && !a->NonResident) {
            const ATTR_RESIDENT_EXT* r =
                (const ATTR_RESIDENT_EXT*)(buf + offset + sizeof(ATTR_HEADER));
            const FILE_NAME_ATTR* fn =
                (const FILE_NAME_ATTR*)(buf + offset + r->ValueOffset);

            char name[512] = {};
            WideCharToMultiByte(CP_ACP, 0,
                fn->FileName, fn->FileNameLength,
                name, sizeof(name) - 1, NULL, NULL);

            if (StrEqNoCase(std::string(name), target)) {
                PrintMatch(sector, hdr, fn, name);
                return true;
            }
        }

        offset += a->Length;
    }
    return false;
}

int main(int argc, char* argv[])
{

    if (argc < 4) {
        printf("  Find_File_By_Name.exe <start_sector> <end_sector> <filename> [drive]\n\n");

        return 1;
    }

    ULONGLONG startSector = strtoull(argv[1], nullptr, 10);
    ULONGLONG endSector = strtoull(argv[2], nullptr, 10);
    std::string target = argv[3];
    int driveIdx = (argc >= 5) ? atoi(argv[4]) : 0;

    HANDLE hDisk = CreateFileW(L"\\\\.\\PhysicalDrive0", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);

    if (hDisk == INVALID_HANDLE_VALUE) {
        printf("[!] Run as Administrator.\n");
        return 1;
    }

    printf("[+] Start Sector : %llu\n", startSector);
    printf("[+] End Sector   : %llu\n", endSector);
    printf("[+] Searching for: \"%s\"\n\n", target.c_str());

    ULONGLONG totalRecords = 0;
    ULONGLONG foundCount = 0;
    BYTE      buf[1024] = {};
    DWORD     bytesRead = 0;

    for (ULONGLONG sector = startSector;
        sector + 1 <= endSector;
        sector += 2)
    {
        LARGE_INTEGER li;
        li.QuadPart = (LONGLONG)(sector * 512ULL);

        if (!SetFilePointerEx(hDisk, li, NULL, FILE_BEGIN)) continue;

        bytesRead = 0;
        if (!ReadFile(hDisk, buf, 1024, &bytesRead, NULL) || bytesRead != 1024)
            continue;

        totalRecords++;

        if (totalRecords % 10000 == 0)
            printf("[#] Scanning... record #%llu  \r", totalRecords);

        if (ScanRecord(buf, sector, target))
            foundCount++;
    }

    CloseHandle(hDisk);


    return 0;
}