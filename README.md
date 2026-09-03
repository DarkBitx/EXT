# EXT — Export Directory Extractor

## Overview

**EXT (Export Directory Extractor)** is a Windows PE analysis tool designed to simplify DLL export analysis and automate the generation of proxy DLL boilerplate.

The tool extracts exported functions from Windows DLL files and generates the required files commonly used during DLL proxy research, including export forwarding definitions and function templates.

## Features

- Extract exported functions from Windows DLL files
- Generate `#pragma comment(linker)` export forwarding directives
- Generate `.def` export definition files
- Generate function templates for manual export handling
- Automatically detect DLL forwarding names
- Support custom forwarding DLL prefixes

## Generated Files

EXT can generate:

### `Source.txt`

Contains linker directives for forwarding exports:

```c
#pragma comment(linker, "/export:FunctionName=original_dll.FunctionName,@Ordinal")
```

### `Source.def`

Contains exported function mappings:

```def
LIBRARY

EXPORTS
    FunctionName=original_dll.FunctionName @Ordinal
```

### `Functions.txt`

Contains function templates that can be customized for manual handling:

```c
PVOID FunctionName() {
    MessageBoxA(NULL, "Function intercepted!", "EXT", MB_OK);
    return NULL;
}
```

## Installation

Install the required dependency:

```bash
pip install pefile
```

Clone the repository:

```bash
git clone https://github.com/DarkBitx/EXT.git
```

## Usage

Basic usage:

```bash
python EXT.py target.dll
```

By default, EXT generates all available output files:

```
Source.txt
Source.def
Functions.txt
```

### Generate Specific Outputs

Generate linker directives:

```bash
python EXT.py target.dll --inline
```

Generate definition file:

```bash
python EXT.py target.dll --deff
```

Generate function templates:

```bash
python EXT.py target.dll --func
```

### Custom Output Directory

```bash
python EXT.py target.dll --output-dir ./output
```

### Custom Forward DLL Name

```bash
python EXT.py target.dll --prefix custom_name
```

## Example

Analyze a DLL:

```bash
python EXT.py jli.dll
```

Output:

```
[+] Generated inline directives: Source.txt
[+] Generated .def file: Source.def
[+] Generated function stubs: Functions.txt

[+] Extraction complete.
```

## Workflow

```
Windows DLL
     |
     v
Export Directory Analysis
     |
     v
EXT
     |
     +── Source.txt
     |
     +── Source.def
     |
     +── Functions.txt
```

## Author

[**DarkBit**](https://t.me/DarkBitx)
