/*
Example: create a Portable Executable (PE) file (x86) from user-provided x86 instructions.

This C program is a small, educational example that shows how to assemble a minimal PE
executable by supplying raw x86 machine code and data buffers, then using the helper
library defined in "pe_header.h" to build PE headers and sections, and final .exe file.

Workflow demonstrated:
- allocate buffers for .text (code), .data and .rdata
- copy user x86 instructions into the code buffer and any static data into the data buffer
- call createEXE(...) from pe_header.h to construct a "my_compiled_program.exe" file

Notes:
- Intended only as an example / learning aid.
- Adjust SIZE_CODE / SIZE_DATA / SIZE_RDATA and the x86 bytes as needed.

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
#include <stdio.h>
#include "pe_header.h"

#define SIZE_CODE 6040
#define SIZE_DATA 100
#define SIZE_RDATA 1440


int main(int argc, char const *argv[]){
    unsigned i;
    BYTE *x86sourceCode = (BYTE*)calloc(SIZE_CODE, sizeof(BYTE));
    BYTE *data = (BYTE*)calloc(SIZE_DATA, sizeof(BYTE));
    BYTE *rdata = (BYTE*)calloc(SIZE_RDATA, sizeof(BYTE));

    const char DATA[] = "This is a string stored at the beginning of the .data section :D";

    // Example of a user-provided x86 code (it first makes a beep sound and then prints the message in DATA above)
    const char x86CODE[] =
        // -- BOOL Beep(_in_ DWORD dwFreq, _in_ DWORD dwDuration) --
        // Push the duration of the beep sound onto the stack
        "\x68\x00\x10\x00\x00" // PUSH 0x00001000 (dwDuration)
        // Push the frequency of the beep sound onto the stack
        "\x68\xFF\x00\x00\x00" // PUSH 0x000000FF (dwFreq)
        // Call the Beep function from Kernel32.dll
        "\xFF\x15\xA4\x51\x40\x00" // CALL DWORD PTR [KERNEL32.DLL!Beep(dwFreq, dwDuration)]

        // -- HANDLE WINAPI GetStdHandle(_In_ DWORD nStdHandle) --
        // Push -11, the standard handle for the console output, onto the stack (-10 STR_INPUT_HANDLE, -11 STR_OUTPUT_HANDLE, -12 STR_ERROR_HANDLE)
        "\x68\xF5\xFF\xFF\xFF" // PUSH 0xFFFFFFF5[*] nStdHandle ([*] -11 2-Complement = [invertbits(11d)+1])
        // Call GetStdHandle to get the console output handle
        "\xFF\x15\x44\x51\x40\x00" // CALL DWORD PTR [KERNEL32.DLL!GetStdHandle(...)]

        // -- BOOL WINAPI WriteConsole(_In_ HANDLE  hConsoleOutput, _In_ const VOID *lpBuffer, _In_ DWORD nNumberOfCharsToWrite, _Out_ LPDWORD lpNumberOfCharsWritten, _Reserved_ LPVOID lpReserved) --
        // Push a NULL pointer for lpReserved onto the stack
        "\x68\x00\x00\x00\x00" // PUSH 0x00000000 (lpReserved)
        // Push a NULL pointer for lpNumberOfCharsWritten onto the stack
        "\x68\x00\x00\x00\x00" // PUSH 0x00000000 (lpNumberOfCharsWritten)
        // Push the number of characters to write, 65, onto the stack
        "\x68\x41\x00\x00\x00" // PUSH 0x00000041 (nNumberOfCharsToWrite)
        // Push the address of the buffer (.data) containing the string onto the stack
        "\x68\x00\x30\x40\x00" // PUSH 0x0000003C (*lpBuffer)
        // Push the console output handle onto the stack
        "\x50" // PUSH EAX (hConsoleOutput)
        // Call WriteConsole to write the string to the console
        "\xFF\x15\xA8\x51\x40\x00" // CALL DWORD PTR [KERNEL32.DLL!WriteConsole(...)]

        // -- VOID WINAPI ExitProcess(_In_ UINT uExitCode) --
        // Push the exit code 0 onto the stack
        "\x68\x00\x00\x00\x00" // PUSH 0x00000000 (uExitCode)
        // Call ExitProcess to terminate the process
        "\xFF\x15\x08\x51\x40\x00"; // CALL DWORD PTR [KERNEL32.DLL!ExitProcess(uExitCode)]

    memcpy(x86sourceCode, x86CODE, sizeof(x86CODE));
    memcpy(data, DATA, sizeof(DATA));

    EXE_FILE* exe = createEXE(x86sourceCode, data, rdata, SIZE_CODE, SIZE_DATA, SIZE_RDATA);

    FILE* file = fopen("my_compiled_program.exe", "wb");

    fwrite(exe->dosHeader, sizeof(IMAGE_DOS_HEADER), 1, file);
    fwrite(exe->dosStubCode, sizeof(IMAGE_DOS_HEADER_STUB_CODE), 1, file);
    fwrite(exe->ntHeaders, sizeof(IMAGE_NT_HEADERS), 1, file);
    fwrite(exe->sectionTable, sizeof(IMAGE_SECTION_HEADER), exe->ntHeaders->FileHeader.NumberOfSections, file);
    for (; ftell(file) < PEXE->sectionTable[0].PointerToRawData;){fprintf(file, "%c", 0x00);}

    for (i = 0; i < exe->ntHeaders->FileHeader.NumberOfSections; ++i){
        fwrite(exe->sections[i], PEXE->sectionTable[i].Misc.VirtualSize, 1, file);
        for (; ftell(file) < PEXE->sectionTable[i].PointerToRawData + PEXE->sectionTable[i].SizeOfRawData;){fprintf(file, "%c", 0x00);}
    }

    fclose(file);

    free(exe->dosHeader);
    free(exe->sectionTable);
    for (i = 0; i < exe->ntHeaders->FileHeader.NumberOfSections; ++i)
        free(exe->sections[i]);
    free(exe->ntHeaders);
    //free(exe->sections);
    free(exe);

    return 0;
}
