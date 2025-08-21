# PE EXE Creator

A minimal C project for creating Windows PE (Portable Executable) EXE files. This repository contains:

- `pe_header.h`: Header library for building and manipulating PE file structures programmatically.
- `example.c`: Example program that demonstrates how to generate a minimal PE executable from raw x86 machine code and data buffers using the library.

## Features
- Build PE headers and sections from user-provided x86 instructions and data.
- Generate a working `.exe` file for Windows (x86).
- Educational and easy to modify for your own experiments.

## Usage
1. Clone or download this repository.
2. Compile the example:

```sh
gcc example.c -o run_example
```

3. Run the example (on Windows):

```sh
./run_example
```

This will generate `my_compiled_program.exe` in the current directory.

## License
MIT License. See source files for details.
