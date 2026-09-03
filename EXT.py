"""
Export Directory Extractor v1.0
Extract exported functions from a Windows DLL and generate proxy boilerplate:
- #pragma comment(linker) directives (Source.txt)
- .def file (Source.def)
- Function stubs for manual interception (Functions.txt)

Author: DarkBit
GitHub: https://github.com/DarkBitx
"""

import sys
import re
import argparse
from pathlib import Path

try:
    import pefile
except ImportError:
    print("[!] Missing required library: pefile")
    print("    Install with: pip install pefile")
    sys.exit(1)

BANNER = r"""
 /$$$$$$$$ /$$   /$$ /$$$$$$$$
| $$_____/| $$  / $$|__  $$__/
| $$      |  $$/ $$/   | $$   
| $$$$$    \  $$$$/    | $$   
| $$__/     >$$  $$    | $$   
| $$       /$$/\  $$   | $$   
| $$$$$$$$| $$  \ $$   | $$   
|________/|__/  |__/   |__/   
                              
        Export Directory Extractor v1.0
          by DarkBit – https://github.com/DarkBitx
"""

def extract_base_name(dll_path: str):
    dll_name = Path(dll_path).name
    base = re.sub(r'\.dll$', '_dll', dll_name, flags=re.IGNORECASE)
    return base


def generate_inline(pe: pefile.PE, base_name: str, output_file: Path):
    lines = []
    for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
        if not exp.name:
            continue
        fn = exp.name.decode()
        ordn = exp.ordinal
        lines.append(
            f'#pragma comment(linker, "/export:{fn}={base_name}.{fn},@{ordn}")'
        )
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write("\n".join(lines))


def generate_def(pe: pefile.PE, base_name: str, output_file: Path):
    lines = ["LIBRARY", "EXPORTS"]
    for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
        if not exp.name:
            continue
        fn = exp.name.decode()
        ordn = exp.ordinal
        lines.append(f"    {fn}={base_name}.{fn} @{ordn}")
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write("\n".join(lines))


def generate_stubs(pe: pefile.PE, output_file: Path):
    lines = []
    for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
        if not exp.name:
            continue
        fn = exp.name.decode()
        stub = f"""PVOID {fn}() {{
    MessageBoxA(NULL, "Persist installed by {fn}!", "DarkBit", MB_OK | MB_ICONEXCLAMATION);
    return NULL;
}}"""
        lines.append(stub)
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write("\n\n".join(lines))

def main():

    print(BANNER)
    
    parser = argparse.ArgumentParser(
        description="Extract exports from a Windows DLL and generate proxy boilerplate.",
        epilog="Example: python export_extractor.py C:\\Windows\\System32\\jli.dll --inline --func"
    )
    parser.add_argument(
        'dll_path',
        type=str,
        help='Path to the target DLL file.'
    )
    parser.add_argument(
        '--inline',
        action='store_true',
        help='Generate #pragma comment(linker) lines (Source.txt).'
    )
    parser.add_argument(
        '--deff',
        action='store_true',
        help='Generate a .deff file (Source.deff).'
    )
    parser.add_argument(
        '--func',
        action='store_true',
        help='Generate function stubs for manual proxying (Functions.txt).'
    )
    parser.add_argument(
        '--output-dir',
        type=str,
        default='.',
        help='Output directory for generated files (default: current directory).'
    )
    parser.add_argument(
        '--prefix',
        type=str,
        default=None,
        help='Custom base name for forwarded DLL (default: auto-derived from DLL name).'
    )

    args = parser.parse_args()

    dll_path = Path(args.dll_path)
    if not dll_path.exists():
        print(f"[!] DLL file not found: {dll_path}")
        sys.exit(1)

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    if args.prefix:
        base_name = args.prefix
    else:
        base_name = extract_base_name(str(dll_path))

    try:
        pe = pefile.PE(str(dll_path))
    except Exception as e:
        print(f"[!] Failed to load PE: {e}")
        sys.exit(1)

    if not hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
        print("[!] No export table found in the DLL.")
        sys.exit(1)

    if not (args.inline or args.deff or args.func):
        args.inline = args.deff = args.func = True

    try:
        if args.inline:
            out_file = output_dir / "Source.txt"
            generate_inline(pe, base_name, out_file)
            print(f"[+] Generated inline directives: {out_file}")

        if args.deff:
            out_file = output_dir / "Source.def"
            generate_def(pe, base_name, out_file)
            print(f"[+] Generated .def file: {out_file}")

        if args.func:
            out_file = output_dir / "Functions.txt"
            generate_stubs(pe, out_file)
            print(f"[+] Generated function stubs: {out_file}")

        print("\n[+] Extraction complete. Happy proxying!")

    except Exception as e:
        print(f"[!] Error during generation: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()