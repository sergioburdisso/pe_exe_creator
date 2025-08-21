/*
This header file contains definitions and structures for parsing
and working with the Portable Executable (PE) file format on x86 architecture.

The PE file format is used in Windows operating systems for executables, object code, 
and DLLs. This file provides the necessary declarations to interpret the PE headers 
and create PE files.

The MIT License (MIT)

Copyright (c) 2016 Burdisso Sergio

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
 */
#ifndef __PE_HEADER__
#define __PE_HEADER__

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/****** CONSTANTS, ENUM AND TYPEDEFS ******/
// Signatures
#define IMAGE_DOS_SIGNATURE  0x5A4D      // "MZ"(in little endian)
#define IMAGE_NT_SIGNATURE   0x00004550  // "PE\0\0"(in little endian) -> Portable Executable Windows file

// IMAGE_FILE_HEADER.Machine
#define IMAGE_FILE_MACHINE_I386    0x014C // x86
#define IMAGE_FILE_MACHINE_AMD64   0x8664 // x64

// IMAGE_FILE_HEADER.Characteristics
#define IMAGE_FILE_RELOCS_STRIPPED           0x0001 // Relocation information stripped from a file.
#define IMAGE_FILE_EXECUTABLE_IMAGE          0x0002 // The file is executable.
#define IMAGE_FILE_LINE_NUMS_STRIPPED        0x0004 // COFF line numbers were stripped from the file
#define IMAGE_FILE_AGGRESIVE_WS_TRIM         0x0010 // Lets the OS aggressively trim the working set.
#define IMAGE_FILE_LARGE_ADDRESS_AWARE       0x0020 // The application can handle addresses greater than two gigabytes.
#define IMAGE_FILE_32BIT_MACHINE             0x0100 // This requires a 32-bit word machine.
#define IMAGE_FILE_DEBUG_STRIPPED            0x0200 // Debug information is stripped to a .DBG file.
#define IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP   0x0400 // If the image is on removable media, copy to and run from the swap file.
#define IMAGE_FILE_NET_RUN_FROM_SWAP         0x0800 // If the image is on a network, copy to and run from the swap file.
#define IMAGE_FILE_DLL                       0x2000 // The file is a DLL.
#define IMAGE_FILE_UP_SYSTEM_ONLY            0x4000 // The file should only be run on single-processor machines.
#define IMAGE_FILE_LOCAL_SYMS_STRIPPED       0x0008

//  IMAGE_OPTIONAL_HEADER.Magic
#define IMAGE_NT_OPTIONAL_HDR32_MAGIC   0x010B
#define IMAGE_NT_OPTIONAL_HDR64_MAGIC   0x020B

// IMAGE_OPTIONAL_HEADER.Subsystem
#define IMAGE_SUBSYSTEM_NATIVE         1 // No subsystem required (device drivers and native system processes)
#define IMAGE_SUBSYSTEM_WINDOWS_GUI    2 // Windows graphical user interface (GUI) subsystem
#define IMAGE_SUBSYSTEM_WINDOWS_CUI    3 // Windows character-mode user interface (CUI) subsystem. i.e run as a console
                                         // mode application. When run, the OS creates a console window for it, and
                                         // provides stdin, stdout, and stderr file handles.

// IMAGE_OPTIONAL_HEADER.DataDictionary[IMAGE_DIRECTORY_ENTRY_xxx]
#define IMAGE_DIRECTORY_ENTRY_EXPORT             0 // Points to the exports (an IMAGE_EXPORT_DIRECTORY structure).
#define IMAGE_DIRECTORY_ENTRY_IMPORT             1 // Points to the imports (an array of IMAGE_IMPORT_DESCRIPTOR structures).
#define IMAGE_DIRECTORY_ENTRY_RESOURCE           2 // Points to the resources (an IMAGE_RESOURCE_DIRECTORY structure).
#define IMAGE_DIRECTORY_ENTRY_EXCEPTION          3 // Points to the exception handler table (an array of IMAGE_RUNTIME_FUNCTION_ENTRY structures)
#define IMAGE_DIRECTORY_ENTRY_SECURITY           4 // Points to a list of WIN_CERTIFICATE structures, defined in WinTrust.H.
#define IMAGE_DIRECTORY_ENTRY_BASERELOC          5 // Points to the base relocation information.
#define IMAGE_DIRECTORY_ENTRY_DEBUG              6 // Points to an array of IMAGE_DEBUG_DIRECTORY structures, each describing some debug information for the image. 
#define IMAGE_DIRECTORY_ENTRY_ARCHITECTURE       7 // Points to architecture-specific data, which is an array of IMAGE_ARCHITECTURE_HEADER structures. Not used for x86 or IA-64.
#define IMAGE_DIRECTORY_ENTRY_GLOBALPTR          8 // The VirtualAddress field is the RVA to be used as the global pointer (gp) on certain architectures. Not used on x86.
#define IMAGE_DIRECTORY_ENTRY_TLS                9 // Points to the Thread Local Storage initialization section.
#define IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG       10 // Points to an IMAGE_LOAD_CONFIG_DIRECTORY structure. 
#define IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT      11 // Points to an array of IMAGE_BOUND_IMPORT_DESCRIPTORs, one for each DLL that this image has bound against.
#define IMAGE_DIRECTORY_ENTRY_IAT               12 // Points to the beginning of the first Import Address Table (IAT). The IATs for each imported DLL appear sequentially
                                                   // in memory. The Size field indicates the total size of all the IATs. The loader uses this address and size to temporarily
                                                   // mark the IATs as read-write during import resolution. (default 0)
#define IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT      13 // Points to the delayload information, which is an array of CImgDelayDescr structures, defined in DELAYIMP.H from Visual C++.
#define IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR    14 // This value has been renamed to IMAGE_DIRECTORY_ENTRY_COMHEADER in more recent updates to the system header files. It points to
                                                   // the top-level information for .NET information in the executable, including metadata. This information is in the form of an IMAGE_COR20_HEADER structure.
#define IMAGE_DIRECTORY_ENTRY_RESERVED          15 // Reserved

// IMAGE_THUNK_DATA (mask)
#define IMAGE_ORDINAL_FLAG 0x80000000
#define IMAGE_ORDINAL(Ordinal) (Ordinal & 0xffff)

// IMAGE_SECTION_HEADER.Characteristics
#define IMAGE_SCN_CNT_CODE                  0x00000020 // The section contains code.
#define IMAGE_SCN_MEM_EXECUTE               0x20000000 // The section is executable.
#define IMAGE_SCN_CNT_INITIALIZED_DATA      0x00000040 // The section contains initialized data.
#define IMAGE_SCN_CNT_UNINITIALIZED_DATA    0x00000080 // The section contains uninitialized data.
#define IMAGE_SCN_MEM_DISCARDABLE           0x02000000 // The section can be discarded from the final executable. (e.g. debug$ sections)
#define IMAGE_SCN_MEM_NOT_PAGED             0x08000000 // The section is not pageable, so it should always be physically
                                                       // present in memory. Often used for kernel-mode drivers.
#define IMAGE_SCN_MEM_SHARED                0x10000000 // The physical pages containing this section's data will be shared between
                                                       // all processes that have this executable loaded. Thus, every process will see the
                                                       // exact same values for data in this section. Useful for making global variables
                                                       // shared between all instances of a process.
#define IMAGE_SCN_MEM_READ                  0x40000000 // The section is readable. Almost always set.
#define IMAGE_SCN_MEM_WRITE                 0x80000000 // The section is writeable.
#define IMAGE_SCN_ALIGN_1BYTES              0x00100000 //
#define IMAGE_SCN_ALIGN_2BYTES              0x00200000 //
#define IMAGE_SCN_ALIGN_4BYTES              0x00300000 //
#define IMAGE_SCN_ALIGN_8BYTES              0x00400000 //
#define IMAGE_SCN_ALIGN_16BYTES             0x00500000 //
#define IMAGE_SCN_ALIGN_32BYTES             0x00600000 // => Align data on a N-byte boundary
#define IMAGE_SCN_ALIGN_64BYTES             0x00700000 //
#define IMAGE_SCN_ALIGN_128BYTES            0x00800000 //
#define IMAGE_SCN_ALIGN_256BYTES            0x00900000 //
#define IMAGE_SCN_ALIGN_512BYTES            0x00A00000 //
#define IMAGE_SCN_ALIGN_1024BYTES           0x00B00000 //
#define IMAGE_SCN_ALIGN_2048BYTES           0x00C00000 //
#define IMAGE_SCN_ALIGN_4096BYTES           0x00D00000 //
#define IMAGE_SCN_ALIGN_8192BYTES           0x00E00000 //

#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES 16

typedef  uint8_t BYTE;    //  8 bits unsigned
typedef uint16_t WORD;    // 16 bits unsigned
typedef uint32_t DWORD;   // 32 bits unsigned
typedef  int32_t LONG;    // 32 bits signed

typedef unsigned int UINT;
typedef        void* PVOID;
typedef        PVOID HANDLE;

/****** HEADERS ******/

// https://msdn.microsoft.com/en-us/library/windows/desktop/ms680305(v=vs.85).aspx
typedef struct _IMAGE_DATA_DIRECTORY_ {
    DWORD VirtualAddress; // The relative virtual address (RVA) of the table (e.g. in case of Import, the RVA of
                          // the .idata section, which at the beginning contains the table, --an array of 
                          // IMAGE_IMPORT_DESCRIPTOR structures, terminated by a NULL structure - all 0's).

    DWORD Size;           // The size of the section, in bytes (e.g. .idata for import).
} IMAGE_DATA_DIRECTORY;

// Figure 5 (Figures Part 2.htm)
// One per each imported DLL
typedef struct _IMAGE_IMPORT_DESCRIPTOR_ {
    DWORD OriginalFirstThunk; // This field is badly named. It contains the RVA of the "Import Name Table" (INT, aka Hint-Name Table).
                              // INT is an array of IMAGE_THUNK_DATA structures, terminated by a NULL IMAGE_THUNK_DATA structures entry
                              // at the end array.
                              // This field is set to 0 to indicate no INT is used (Only IAT).

    DWORD TimeDateStamp;      // This is 0 if this executable is not bound against the imported DLL. When binding
                              // in the old style (see the section on Binding), this field contains the Unix/Epoch
                              // time when the binding occurred. When binding in the new style, this field is set to -1.

    DWORD ForwarderChain;     // This is the Index of the first forwarded API. Set to -1 (0xFFFFFFFF) if no forwarders.
                              // Only used for old-style binding, which could not handle forwarded APIs efficiently.

    DWORD Name;               // The RVA of a NULL-terminated ASCII string with the name of the imported DLL (e.g. "KERNEL32.DLL\0")
    DWORD FirstThunk;         // Contains the RVA of the "Import Address Table" (IAT). IAT is an array of
                              // IMAGE_THUNK_DATA structures, terminated by a NULL pointer entry at the end array.
                              // This array is going to be overwritten by the PE loader, replacing every entry/pointer to
                              // each imported funtion's IMAGE_IMPORT_BY_NAME by its address.
} IMAGE_IMPORT_DESCRIPTOR;

// "The Imports Section" from "Inside Windows An In-Depth Look into the Win32 Portable Executable File Format, Part 2"
// (one per each DLL's funtion imported)
typedef struct _IMAGE_THUNK_DATA_ {
    DWORD AddressOfData;    // RVA to an IMAGE_IMPORT_BY_NAME with the imported API name.
    /*union {
        DWORD AddressOfData;    // RVA to an IMAGE_IMPORT_BY_NAME with the imported API name.
        DWORD Function;            // Memory address of the imported function.

        DWORD Ordinal;            // Ordinal value of imported API.
        DWORD ForwarderString;    // RVA to a forwarder string.
    } u1;*/
} IMAGE_THUNK_DATA;

// for storing each imported function name
// (see Figure 6. from "Inside Windows An In-Depth Look into the Win32 Portable Executable File Format, Part 2")
typedef struct _IMAGE_IMPORT_BY_NAME_ {
    WORD Hint;      // The best guess as to what the export ordinal for the imported function is. This value
                    // doesn't have to be correct. Instead, the loader uses it as a suggested starting value
                    // for its binary search for the exported function. (defualt 0).

    BYTE Name[1];   // ASCIIZ string with the name of the imported function.
} IMAGE_IMPORT_BY_NAME;

// https://msdn.microsoft.com/en-us/library/windows/desktop/ms680313(v=vs.85).aspx
typedef struct _IMAGE_FILE_HEADER_ {
    WORD  Machine;              // The target CPU for this executable (values IMAGE_FILE_MACHINE_xxx).
    WORD  NumberOfSections;     // Indicates how many sections are in the section table (which follows the IMAGE_NT_HEADERS).
    DWORD TimeDateStamp;        // Indicates the time when the file was created (Unix/Epoch time).
    DWORD PointerToSymbolTable; // The file offset of the COFF symbol table (Debugger - 0 if no symbol table is present).
    DWORD NumberOfSymbols;      // Number of symbols in the COFF symbol table, if present.
    WORD  SizeOfOptionalHeader; // The size of the optional data that follows the IMAGE_FILE_HEADER ( sizeof IMAGE_OPTIONAL_HEADER ).
    WORD  Characteristics;      // A set of bit flags indicating attributes of the file (values of IMAGE_FILE_xxx OR'ed together).
} IMAGE_FILE_HEADER;

// https://msdn.microsoft.com/en-us/library/windows/desktop/ms680339(v=vs.85).aspx
// Figure 5. (Figures Part1.html)
typedef struct _IMAGE_OPTIONAL_HEADER_ {
    WORD  Magic;                        // The state of the image file (values: IMAGE_NT_OPTIONAL_HDRxxx)
    BYTE  MajorLinkerVersion;           // The major version number of the linker
    BYTE  MinorLinkerVersion;           // The minor version number of the linker
    DWORD SizeOfCode;                   // The size of the code section, in bytes, or the sum of all such sections
                                        // if there are multiple code sections. That is, the combined total size of
                                        // all sections with the IMAGE_SCN_CNT_CODE attribute (mult of FileAligment).

    DWORD SizeOfInitializedData;        // The size of the initialized data section, in bytes, or the sum of all
                                        // such sections if there are multiple initialized data sections (mult of FileAligment).

    DWORD SizeOfUninitializedData;      // The size of the uninitialized data section, in bytes, or the sum of all
                                        // such sections if there are multiple uninitialized data sections.

    DWORD AddressOfEntryPoint;          // A pointer to the entry point function, relative to the image base address.
                                        // i.e. The RVA of the first code byte in the file that will be executed.
                                        // For executable files, this is the starting address. For device drivers,
                                        // this is the address of the initialization function. The entry point function
                                        // is optional for DLLs. When no entry point is present, this member is zero.

    DWORD BaseOfCode;                   // A pointer to the beginning of the code section, relative to the image base.
                                        // i.e. The RVA of the first byte of code when loaded in memory.

    DWORD BaseOfData;                   // A pointer to the beginning of the data section, relative to the image base.
                                        // Theoretically, the RVA of the first byte of data when loaded into memory.
                                        // However, the values for this field are inconsistent with different versions
                                        // of the Microsoft linker. This field is not present in 64-bit executables.

    DWORD ImageBase;                    // The preferred address of the first byte of the image when it is loaded in
                                        // memory. The loader attempts to load the PE file at this address if possible
                                        // (that is, if nothing else currently occupies that memory, it's aligned properly
                                        // and at a legal address, and so on). This value is a multiple of 64K bytes.
                                        // The default value for DLLs is 0x10000000. The default value for applications
                                        // is 0x00400000.

    DWORD SectionAlignment;             // The alignment of sections loaded in memory, in bytes. This value must be
                                        // greater than or equal to the FileAlignment member. The default value is
                                        // the page size for the system (e.g. 4K bytes - 0x00001000).

    DWORD FileAlignment;                // The alignment of the raw data of sections in the image file, in bytes
                                        // The value should be a power of 2 between 512 and 64K (inclusive).
                                        // The default is 512 (0x00000200).

    WORD  MajorOperatingSystemVersion;  // The major version number of the required operating system. With the advent
                                        // of so many versions of Windows, this field has effectively become irrelevant.

    WORD  MinorOperatingSystemVersion;  // The minor version number of the required operating system
    WORD  MajorImageVersion;            // The major version number of the image
    WORD  MinorImageVersion;            // The minor version number of the image
    WORD  MajorSubsystemVersion;        // The major version number of the subsystem
    WORD  MinorSubsystemVersion;        // The minor version number of the subsystem
    DWORD Win32VersionValue;            // This member is reserved and must be 0
    DWORD SizeOfImage;                  // Contains the RVA that would be assigned to the section following the last section
                                        // if it existed. This is effectively the amount of memory that the system needs to 
                                        // reserve when loading this file into memory. This field must be a multiple of the section alignment.

    DWORD SizeOfHeaders;                // The combined size of the following items, rounded to a multiple of the value
                                        // specified in the FileAlignment member:
                                        // roundto(sizeof(IMAGE_DOS_HEADER.e_lfanew + IMAGE_NT_HEADERS32 + all section headers), FileAlignment).

    DWORD CheckSum;                     // The image file checksum. The CheckSumMappedFile API in IMAGEHLP.DLL can
                                        // calculate this value. Checksums are required for kernel-mode drivers and
                                        // some system DLLs. Otherwise, this field can be 0. The checksum is placed
                                        // in the file when the /RELEASElinker switch is used.

    WORD  Subsystem;                    // An enum value indicating what subsystem (user interface type) the executable
                                        // expects. This field is only important for EXEs (values: IMAGE_SUBSYSTEM_xxx).

    WORD  DllCharacteristics;           // Flags indicating characteristics of this DLL
    DWORD SizeOfStackReserve;           // In EXE files, the maximum size the initial thread in the process can grow to.
                                        // This is 1MB (0x00100000) by default. I.e. The number of bytes to reserve for
                                        // the stack. Only the memory specified by the SizeOfStackCommit member is committed
                                        // at load time; the rest is made available one page at a time until this reserve size is reached.

    DWORD SizeOfStackCommit;            // In EXE files, the amount of memory initially committed to the stack. By default,
                                        // this field is 4KB (0x00002000).

    DWORD SizeOfHeapReserve;            // In EXE files, the initial reserved size of the default process heap.
                                        // This is 1MB (0x00100000) by default. I.e. The number of bytes to reserve for the local heap.
                                        // Only the memory specified by the SizeOfHeapCommit member is committed at load time;
                                        // the rest is made available one page at a time until this reserve size is reached.

    DWORD SizeOfHeapCommit;             // In EXE files, the size of memory committed to the heap. By default, this is 4KB (0x00002000).
    DWORD LoaderFlags;                  // This is obsolete.
    DWORD NumberOfRvaAndSizes;          // The number of directory entries in the remainder of the optional header.
                                        // Each entry describes a location and size. This field has been 16
                                        // since the earliest releases of Windows NT.

    IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES]; // An array of IMAGE_DATA_DIRECTORY structures. Each structure
                                                                          // contains the RVA and size of some important part of the
                                                                          // executable (for instance, imports, exports, resources).
} IMAGE_OPTIONAL_HEADER;

typedef struct _IMAGE_DOS_HEADER_ {
    WORD e_magic;    // "MZ"(in little endian)
    WORD e_cblp;     // Number of bytes in the last page
    WORD e_cp;       // Number of whole/partial pages
    WORD e_crlc;     // Number of entries in the relocation table
    WORD e_cparhdr;  // The number of paragraphs taken up by the header (1 paragraph = 16 bytes)
    WORD e_minalloc; // The number of paragraphs required by the program, excluding the PSP and program image.
    WORD e_maxalloc; // The number of paragraphs requested by the program
    WORD e_ss;       // Relocatable segment address for SS
    WORD e_sp;       // Initial value for SP
    WORD e_csum;     // When added to the sum of all other words in the file, the result should be zero
    WORD e_ip;       // Initial value for IP
    WORD e_cs;       // Relocatable segment address for CS
    WORD e_lfarlc;   // The (absolute) offset to the relocation table
    WORD e_ovno;     // Value used for overlay management. If zero, this is the main executable
    WORD e_res[4];   // Reserved words
    WORD e_oemid;    // OEM identifier (for e_oeminfo)
    WORD e_oeminfo;  // OEM information; e_oemid specific
    WORD e_res2[10]; // Reserved words
    LONG e_lfanew;   // file address to IMAGE_NT_HEADERS
} IMAGE_DOS_HEADER;

BYTE IMAGE_DOS_HEADER_STUB_CODE[64] = "\xBA\x10\x00\x0E\x1F\xB4\x09\xCD\x21\xB8\x01\x4C\xCD\x21\x90\x90" // prints "This program must be run under Win32"
                                      "Este programa debe correr bajo Win32"                             // in Spanish, when run under DOS.
                                      "\x0D\x0A\x24\x37\x00\x00\x00\x00\x00\x00\x00"/*+\x00 added by the compiler (end of string)*/;

// https://msdn.microsoft.com/en-us/library/windows/desktop/ms680336(v=vs.85).aspx
typedef struct _IMAGE_NT_HEADERS_ {
    DWORD Signature;                        // A 4-byte signature identifying the file as a PE image. The bytes are "PE\0\0".
    IMAGE_FILE_HEADER FileHeader;           // An IMAGE_FILE_HEADER structure that specifies the file header.
    IMAGE_OPTIONAL_HEADER OptionalHeader;   // An IMAGE_OPTIONAL_HEADER structure that specifies the optional file header.
} IMAGE_NT_HEADERS;

// https://msdn.microsoft.com/en-us/library/windows/desktop/ms680341(v=vs.85).aspx
// (see Figure 6, Figures Part1.htm)
typedef struct _IMAGE_SECTION_HEADER_ {
    BYTE Name[8];               // The ASCIIZ name of the section.
    union {
        /*DWORD PhysicalAddress;*/
        DWORD VirtualSize;      // The total size of the section when loaded into memory, in bytes. If this
                                // value is greater than the SizeOfRawData member, the section is filled with zeroes.
    } Misc;
    DWORD VirtualAddress;       // The address of the first byte of the section when loaded into memory, relative
                                // to the image base.

    DWORD SizeOfRawData;        // The size of the initialized data on disk, in bytes. This value must be a multiple
                                // of the FileAlignment. If this value is less than the VirtualSize member,
                                // the remainder of the section is filled with zeroes. If the section contains only
                                // uninitialized data, the member is 0.

    DWORD PointerToRawData;     // A file pointer to the first page within the file. This value must be a multiple
                                // of the FileAlignment. If a section contains only uninitialized data, set this 
                                // member to 0.

    DWORD PointerToRelocations; // A file pointer to the beginning of the relocation entries for the section.
                                // (0 for executable images).

    DWORD PointerToLinenumbers; // A file pointer to the beginning of the line-number entries for the section.
                                // Only used when COFF line numbers are emitted otherwise this value is 0.

    WORD NumberOfRelocations;   // The number of relocation entries for the section (0 for executable images).
    WORD NumberOfLinenumbers;   // The number of line-number entries for the section. Only used when COFF line numbers
                                // are emitted otherwise this value is 0.

    DWORD Characteristics;      // Flags OR'ed together, indicating the attributes of this section. (values: IMAGE_SCN_xxx).
} IMAGE_SECTION_HEADER;

#define DEFAULT_IMAGE_BASE   0x00400000
#define DEFAULT_CODE_BASE    0x00001000
#define DEFAULT_IDATA_BASE   0x00006000
#define DEFAULT_NUMBEROF_SECTIONS    4 // .text .data .rdata .idata

#define SECTION_TEXT_INDEX    0
#define SECTION_DATA_INDEX    1
#define SECTION_RDATA_INDEX   2
#define SECTION_IDATA_INDEX   3

typedef struct _EXE_FILE_ {
    IMAGE_DOS_HEADER* dosHeader;
    BYTE* dosStubCode;
    IMAGE_NT_HEADERS* ntHeaders;
    IMAGE_SECTION_HEADER* sectionTable;
    BYTE** sections;
} EXE_FILE;

EXE_FILE *PEXE = NULL;

DWORD roundto(DWORD value, DWORD multiple){
    if (value % multiple)
        return (value/multiple + 1)*multiple;
    else
        return value;
}

IMAGE_IMPORT_BY_NAME* createIMAGE_IMPORT_BY_NAME(WORD Hint, char const *Name){
    IMAGE_IMPORT_BY_NAME *iibn = (IMAGE_IMPORT_BY_NAME*)calloc(1, sizeof(IMAGE_IMPORT_BY_NAME)-1+ strlen(Name));
    iibn->Hint = Hint;
    strcpy((char*)iibn->Name, Name);
    return iibn;
}

unsigned int sizeofIMAGE_IMPORT_BY_NAME(IMAGE_IMPORT_BY_NAME *iibn){ return sizeof(IMAGE_IMPORT_BY_NAME)-1+strlen((const char*)iibn->Name); }

IMAGE_DOS_HEADER* createIMAGE_DOS_HEADER(){
    IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)calloc(1, sizeof(IMAGE_DOS_HEADER));

    dosHeader->e_magic = IMAGE_DOS_SIGNATURE;
    dosHeader->e_cblp = 144;
    dosHeader->e_cp = 3;
    dosHeader->e_cparhdr = sizeof(IMAGE_DOS_HEADER)/16;
    dosHeader->e_maxalloc = 0xFFFF;
    dosHeader->e_sp = 0xB8;
    dosHeader->e_lfarlc = sizeof(IMAGE_DOS_HEADER);
    dosHeader->e_lfanew = dosHeader->e_lfarlc + sizeof(IMAGE_DOS_HEADER_STUB_CODE);

    return dosHeader;
}

IMAGE_NT_HEADERS* createIMAGE_NT_HEADERS(DWORD sizeOfCode){
    IMAGE_NT_HEADERS* ntHeaders = (IMAGE_NT_HEADERS*)calloc(1, sizeof(IMAGE_NT_HEADERS));

    ntHeaders->Signature = IMAGE_NT_SIGNATURE;

    ntHeaders->FileHeader.Machine = IMAGE_FILE_MACHINE_I386;
    ntHeaders->FileHeader.NumberOfSections = DEFAULT_NUMBEROF_SECTIONS;
    ntHeaders->FileHeader.TimeDateStamp = (unsigned)time(NULL);
    ntHeaders->FileHeader.PointerToSymbolTable = 0;
    ntHeaders->FileHeader.NumberOfSymbols = 0;
    ntHeaders->FileHeader.SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER);
    ntHeaders->FileHeader.Characteristics = IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_RELOCS_STRIPPED |
                                            IMAGE_FILE_LINE_NUMS_STRIPPED | IMAGE_FILE_LOCAL_SYMS_STRIPPED |
                                            IMAGE_FILE_LARGE_ADDRESS_AWARE | IMAGE_FILE_32BIT_MACHINE;

    ntHeaders->OptionalHeader.Magic = IMAGE_NT_OPTIONAL_HDR32_MAGIC;
    ntHeaders->OptionalHeader.MajorLinkerVersion = 2; //0?
    ntHeaders->OptionalHeader.MinorLinkerVersion = 24; //0?
    ntHeaders->OptionalHeader.ImageBase = DEFAULT_IMAGE_BASE; // multiple of 64K bytes  (0x10000 bytes)
    ntHeaders->OptionalHeader.SectionAlignment = 4*1024; // 4KB (0x00001000)
    ntHeaders->OptionalHeader.FileAlignment = 512; // (0x00000200)
    ntHeaders->OptionalHeader.MajorOperatingSystemVersion = 4;
    ntHeaders->OptionalHeader.MajorSubsystemVersion = 4;
    ntHeaders->OptionalHeader.MajorImageVersion = 1;
    ntHeaders->OptionalHeader.Subsystem = IMAGE_SUBSYSTEM_WINDOWS_CUI; // Console
    ntHeaders->OptionalHeader.SizeOfStackReserve = 2*1024*1024; // 2MB
    ntHeaders->OptionalHeader.SizeOfStackCommit = 4*1024; // 4KB
    ntHeaders->OptionalHeader.SizeOfHeapReserve = 1*1024*1024; // 1MB
    ntHeaders->OptionalHeader.SizeOfHeapCommit = 4*1024; // 4KB
    ntHeaders->OptionalHeader.NumberOfRvaAndSizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
    ntHeaders->OptionalHeader.SizeOfCode = roundto(sizeOfCode, ntHeaders->OptionalHeader.FileAlignment);
    ntHeaders->OptionalHeader.BaseOfCode = DEFAULT_CODE_BASE;
    ntHeaders->OptionalHeader.BaseOfData = ntHeaders->OptionalHeader.BaseOfCode + roundto(ntHeaders->OptionalHeader.SizeOfCode, ntHeaders->OptionalHeader.SectionAlignment);
    ntHeaders->OptionalHeader.AddressOfEntryPoint = ntHeaders->OptionalHeader.BaseOfCode;
    ntHeaders->OptionalHeader.SizeOfHeaders = roundto(
        sizeof(PEXE->dosHeader->e_lfanew) +
        sizeof(IMAGE_NT_HEADERS) +
        sizeof(IMAGE_SECTION_HEADER)*ntHeaders->FileHeader.NumberOfSections,

        ntHeaders->OptionalHeader.FileAlignment
    );

    return ntHeaders;
}

IMAGE_SECTION_HEADER* createSectionTable(DWORD sizeOfCode, DWORD sizeOfData, DWORD sizeOfRData){
    IMAGE_SECTION_HEADER* sectionTable = (IMAGE_SECTION_HEADER*)calloc(PEXE->ntHeaders->FileHeader.NumberOfSections, sizeof(IMAGE_SECTION_HEADER));

    // .text
    strcpy((char*)sectionTable[SECTION_TEXT_INDEX].Name, ".text");
    sectionTable[SECTION_TEXT_INDEX].VirtualAddress = DEFAULT_CODE_BASE;
    sectionTable[SECTION_TEXT_INDEX].PointerToRawData = roundto(
        sizeof(IMAGE_DOS_HEADER) + sizeof(IMAGE_DOS_HEADER_STUB_CODE) + sizeof(IMAGE_NT_HEADERS) + sizeof(IMAGE_SECTION_HEADER)*PEXE->ntHeaders->FileHeader.NumberOfSections,
        PEXE->ntHeaders->OptionalHeader.FileAlignment
    );
    sectionTable[SECTION_TEXT_INDEX].Misc.VirtualSize = sizeOfCode;
    sectionTable[SECTION_TEXT_INDEX].Characteristics = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE |
                                                       IMAGE_SCN_MEM_READ | IMAGE_SCN_ALIGN_16BYTES |
                                                       IMAGE_SCN_CNT_INITIALIZED_DATA;
    sectionTable[SECTION_TEXT_INDEX].SizeOfRawData = roundto(
        sectionTable[SECTION_TEXT_INDEX].Misc.VirtualSize,
        PEXE->ntHeaders->OptionalHeader.FileAlignment
    );

    // .data
    strcpy((char*)sectionTable[SECTION_DATA_INDEX].Name, ".data");
    sectionTable[SECTION_DATA_INDEX].VirtualAddress = sectionTable[SECTION_TEXT_INDEX].VirtualAddress + roundto(sectionTable[SECTION_TEXT_INDEX].Misc.VirtualSize+1, PEXE->ntHeaders->OptionalHeader.SectionAlignment);
    sectionTable[SECTION_DATA_INDEX].Misc.VirtualSize = sizeOfData;
    sectionTable[SECTION_DATA_INDEX].SizeOfRawData = roundto(sectionTable[SECTION_DATA_INDEX].Misc.VirtualSize, PEXE->ntHeaders->OptionalHeader.FileAlignment);
    sectionTable[SECTION_DATA_INDEX].PointerToRawData = sectionTable[SECTION_TEXT_INDEX].PointerToRawData + sectionTable[SECTION_TEXT_INDEX].SizeOfRawData;
    sectionTable[SECTION_DATA_INDEX].Characteristics = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_ALIGN_32BYTES |
                                                       IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;

    // .rdata
    strcpy((char*)sectionTable[SECTION_RDATA_INDEX].Name, ".rdata");
    sectionTable[SECTION_RDATA_INDEX].VirtualAddress = sectionTable[SECTION_DATA_INDEX].VirtualAddress + roundto(sectionTable[SECTION_DATA_INDEX].Misc.VirtualSize+1, PEXE->ntHeaders->OptionalHeader.SectionAlignment);
    sectionTable[SECTION_RDATA_INDEX].Misc.VirtualSize = sizeOfRData;
    sectionTable[SECTION_RDATA_INDEX].PointerToRawData = sectionTable[SECTION_DATA_INDEX].PointerToRawData + sectionTable[SECTION_DATA_INDEX].SizeOfRawData;
    sectionTable[SECTION_RDATA_INDEX].SizeOfRawData = roundto(sectionTable[SECTION_RDATA_INDEX].Misc.VirtualSize, PEXE->ntHeaders->OptionalHeader.FileAlignment);
    sectionTable[SECTION_RDATA_INDEX].Characteristics = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ |
                                                        IMAGE_SCN_ALIGN_4BYTES;

    // .idata
    strcpy((char*)sectionTable[SECTION_IDATA_INDEX].Name, ".idata");
    sectionTable[SECTION_IDATA_INDEX].VirtualAddress = sectionTable[SECTION_RDATA_INDEX].VirtualAddress + roundto(sectionTable[SECTION_RDATA_INDEX].Misc.VirtualSize+1, PEXE->ntHeaders->OptionalHeader.SectionAlignment);
    sectionTable[SECTION_IDATA_INDEX].PointerToRawData = sectionTable[SECTION_RDATA_INDEX].PointerToRawData + sectionTable[SECTION_RDATA_INDEX].SizeOfRawData;
    sectionTable[SECTION_IDATA_INDEX].Characteristics = IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_ALIGN_4BYTES |
                                                        IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;

    return sectionTable;
}

BYTE* createImportsSection(){
    /*.idata SECTION FORMAT:
        --- start fixed-offsets part ---
        ImportDescriptorTable (one entry per dll)
        1st dll ImportNameTable (one entry per method)
        2nd dll ImportNameTable
        ....
        1st dll ImportAddressTable
        2nd dll ImportAddressTable
        ....
        --- end fixed-offsets part ---
        1st dll Name (variable size)
        1st dll 1st method Hint-NameEntry (variable size)
        1st dll 2st method Hint-NameEntry (variable size)
        ....
        2nd dll Name (variable size)
        2nd dll 1st method Hint-NameEntry (variable size)
        2nd dll 2nd method Hint-NameEntry (variable size)
        ....
    */
    BYTE* importSection;
    unsigned i,j;

    const char* ImportedDlls[]= {"KERNEL32.dll", "USER32.dll"};

    size_t        NbrOfImportedDlls = sizeof(ImportedDlls)/sizeof(const char*);
    const char*    DllMethods[NbrOfImportedDlls][512/*max number of functions per dll*/];
    size_t         DllNbrOfMethods[NbrOfImportedDlls];

    /*KERNEL32.dll*/
    DllMethods[0][ 0]= "CloseHandle";
    DllMethods[0][ 1]= "CreateFileA";
    DllMethods[0][ 2]= "EnterCriticalSection";
    DllMethods[0][ 3]= "ExitProcess";
    DllMethods[0][ 4]= "GetACP";
    DllMethods[0][ 5]= "GetCommandLineA";
    DllMethods[0][ 6]= "GetCPInfo";
    DllMethods[0][ 7]= "GetCurrentThreadId";
    DllMethods[0][ 8]= "GetDateFormatA";
    DllMethods[0][ 9]= "GetEnvironmentStrings";
    DllMethods[0][10]= "GetFileAttributesA";
    DllMethods[0][11]= "GetFileType";
    DllMethods[0][12]= "GetLastError";
    DllMethods[0][13]= "GetLocalTime";
    DllMethods[0][14]= "GetModuleFileNameA";
    DllMethods[0][15]= "GetModuleHandleA";
    DllMethods[0][16]= "GetProcAddress";
    DllMethods[0][17]= "GetStartupInfoA";
    DllMethods[0][18]= "GetStdHandle";
    DllMethods[0][19]= "GetStringTypeW";
    DllMethods[0][20]= "GetVersion";
    DllMethods[0][21]= "GetVersionExA";
    DllMethods[0][22]= "GlobalMemoryStatus";
    DllMethods[0][23]= "InitializeCriticalSection";
    DllMethods[0][24]= "LeaveCriticalSection";
    DllMethods[0][25]= "LocalAlloc";
    DllMethods[0][26]= "LocalFree";
    DllMethods[0][27]= "MultiByteToWideChar";
    DllMethods[0][28]= "RaiseException";
    DllMethods[0][29]= "RtlUnwind";
    DllMethods[0][30]= "SetConsoleCtrlHandler";
    DllMethods[0][31]= "SetFilePointer";
    DllMethods[0][32]= "SetHandleCount";
    DllMethods[0][33]= "TlsAlloc";
    DllMethods[0][34]= "TlsFree";
    DllMethods[0][35]= "TlsGetValue";
    DllMethods[0][36]= "TlsSetValue";
    DllMethods[0][37]= "UnhandledExceptionFilter";
    DllMethods[0][38]= "VirtualAlloc";
    DllMethods[0][39]= "VirtualFree";
    DllMethods[0][40]= "WideCharToMultiByte";
    DllMethods[0][41]= "WriteFile";
    DllMethods[0][42]= "Beep";
    DllMethods[0][43]= "WriteConsoleA";
    DllMethods[0][44]= NULL;

    /*USER32.dll*/
    DllMethods[1][ 0]= "EnumThreadWindows";
    DllMethods[1][ 1]= "MessageBoxA";
    DllMethods[1][ 2]= NULL;

    IMAGE_IMPORT_DESCRIPTOR     *ImportDescriptorTable;
    IMAGE_THUNK_DATA            *DllImportNameTable[NbrOfImportedDlls]; // INT

    DWORD BaseVirtualAddress = PEXE->sectionTable[SECTION_IDATA_INDEX].VirtualAddress;

    size_t NbrOfTotalMethods = 0;
    size_t sizeOfVariableOffsetPart = 0;
    for (i = 0; i < NbrOfImportedDlls; ++i) {
        sizeOfVariableOffsetPart += strlen(ImportedDlls[i]) + 1/*\0*/;

        DllNbrOfMethods[i] = 0;
        for (j = 0; DllMethods[i][j] != NULL; ++j){
            sizeOfVariableOffsetPart += /*Hint*/sizeof(WORD) + /*Name*/strlen(DllMethods[i][j]) + 1/*\0*/;
            DllNbrOfMethods[i]++;
        }
        NbrOfTotalMethods += DllNbrOfMethods[i];
    }

    size_t sizeOfImportDescriptorTable = (NbrOfImportedDlls + 1)*sizeof(IMAGE_IMPORT_DESCRIPTOR);
    size_t sizeOfImportNameTables = (NbrOfTotalMethods + NbrOfImportedDlls/*each table is 0-ed terminated*/)*sizeof(IMAGE_THUNK_DATA);
    size_t sizeOfImportAddressTable = sizeOfImportNameTables;

    size_t sizeOfFixedOffsetPart = sizeOfImportDescriptorTable + sizeOfImportNameTables + sizeOfImportAddressTable;
    size_t sizeOfSection = sizeOfFixedOffsetPart + sizeOfVariableOffsetPart;

    PEXE->ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress = BaseVirtualAddress + sizeOfImportDescriptorTable + sizeOfImportNameTables;
    PEXE->ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size = sizeOfImportAddressTable;

    importSection = (BYTE*)calloc(sizeOfSection, sizeof(BYTE));
    ImportDescriptorTable = (IMAGE_IMPORT_DESCRIPTOR*)importSection;

    BYTE* base_importNameTable = importSection + sizeOfImportDescriptorTable;
    BYTE* base_HintNames = importSection + sizeOfFixedOffsetPart;
    size_t OV = BaseVirtualAddress + sizeOfFixedOffsetPart;
    size_t cur_HintNames = 0;
    size_t cur_ImportNameTable= 0;
    for (i = 0; i < NbrOfImportedDlls; ++i){
        cur_ImportNameTable += (i > 0? DllNbrOfMethods[i-1] + 1/*0-terminated*/ : 0)*sizeof(IMAGE_THUNK_DATA);
        DllImportNameTable[i] = (IMAGE_THUNK_DATA*)(base_importNameTable + cur_ImportNameTable);

        ImportDescriptorTable[i].OriginalFirstThunk = BaseVirtualAddress + sizeOfImportDescriptorTable + cur_ImportNameTable; //INT for the i-th dll
        ImportDescriptorTable[i].FirstThunk = ImportDescriptorTable[i].OriginalFirstThunk + sizeOfImportNameTables; //IAT for the i-th dll
        ImportDescriptorTable[i].Name = OV + cur_HintNames;
        strcpy((char *)(base_HintNames + cur_HintNames), ImportedDlls[i]);
        cur_HintNames += strlen(ImportedDlls[i]) + 1;

        for (j = 0; j < DllNbrOfMethods[i]; ++j){
            DllImportNameTable[i][j].AddressOfData = OV + cur_HintNames;// RVA to the IMAGE_IMPORT_BY_NAME with the imported API name

            cur_HintNames += sizeof(WORD)/*int*/;
            strcpy((char *)(base_HintNames + cur_HintNames), DllMethods[i][j]);
            cur_HintNames += strlen(DllMethods[i][j]) + 1/*\0*/;

        }
    }

    memcpy(base_importNameTable + sizeOfImportNameTables, base_importNameTable, sizeOfImportAddressTable);

    PEXE->sectionTable[SECTION_IDATA_INDEX].Misc.VirtualSize = sizeOfSection;
    PEXE->sectionTable[SECTION_IDATA_INDEX].SizeOfRawData = roundto(
        PEXE->sectionTable[SECTION_IDATA_INDEX].Misc.VirtualSize,
        PEXE->ntHeaders->OptionalHeader.FileAlignment
    );

    PEXE->ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = PEXE->sectionTable[SECTION_IDATA_INDEX].VirtualAddress;
    PEXE->ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size = sizeOfSection;

    return importSection;
}

BYTE** createSections(BYTE* x86sourceCode, BYTE* data, BYTE* rdata){
    BYTE** sections = (BYTE**)calloc(DEFAULT_NUMBEROF_SECTIONS, sizeof(BYTE*));

    sections[SECTION_TEXT_INDEX] = x86sourceCode;
    sections[SECTION_DATA_INDEX] = data;
    sections[SECTION_RDATA_INDEX] = rdata;

    return sections;
}

EXE_FILE* createEXE(BYTE* x86sourceCode, BYTE* data, BYTE* rdata, size_t SizeOfCode, size_t SizeOfData, size_t SizeOfRData){
    // free the previous one!
    PEXE = (EXE_FILE*)calloc(1, sizeof(EXE_FILE));

    PEXE->sections = createSections(x86sourceCode, data, rdata);

    PEXE->dosHeader = createIMAGE_DOS_HEADER();
    PEXE->dosStubCode = IMAGE_DOS_HEADER_STUB_CODE;
    PEXE->ntHeaders = createIMAGE_NT_HEADERS(SizeOfCode);
    PEXE->sectionTable = createSectionTable(SizeOfCode, SizeOfData, SizeOfRData);

    PEXE->sections[SECTION_IDATA_INDEX] = createImportsSection();

    PEXE->ntHeaders->OptionalHeader.SizeOfInitializedData = PEXE->sectionTable[SECTION_TEXT_INDEX].SizeOfRawData +
                                                            PEXE->sectionTable[SECTION_DATA_INDEX].SizeOfRawData +
                                                            PEXE->sectionTable[SECTION_RDATA_INDEX].Misc.VirtualSize +
                                                            PEXE->sectionTable[SECTION_IDATA_INDEX].Misc.VirtualSize;

    PEXE->ntHeaders->OptionalHeader.SizeOfImage = PEXE->sectionTable[SECTION_IDATA_INDEX].VirtualAddress + roundto(PEXE->sectionTable[SECTION_IDATA_INDEX].Misc.VirtualSize+1, PEXE->ntHeaders->OptionalHeader.SectionAlignment);

    return PEXE;
}

#endif /* __PE_HEADER__ */