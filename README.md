# NTFS Forensics Tools

A collection of low-level C++ tools for exploring NTFS disk structures directly via raw disk access (`\\.\PhysicalDrive0`), bypassing the Windows API entirely.

Built as companion tools for the article:
**"From Sector Zero to Hero / Below the API: Extracting Files from Raw Disk Without Windows Knowing"**

https://medium.com/@shakedwe2/from-sector-zero-to-herohttps-miro-medium-com-v2-resize-fit-484-1-o82qispxrb9tx90jrdvw0a-png-e23965b4825c


## Tools:

Sector_HEX_Dumper - Dumps any sector as HEX + ASCII

Sector2_GPT_Partitions - Parses GPT partition entries from Sector 2

NTFS_BOOT_SECTOR - Parses the NTFS Boot Sector — extracts MFT location

MFT_RECORD_HEADER - Reads and displays MFT record headers

MFT_Record_ATTR_HEADER - Walks and displays all attributes of an MFT record

Show_DATA_RUN - Maps raw bytes onto ATTR_HEADER struct (Resident/Non-Resident verdict)

Find_Sector_File - Scans MFT records between two sectors, searching by filename

Read_DATA_Resident_File - Reads and dumps the content of a Resident `$DATA` attribut


