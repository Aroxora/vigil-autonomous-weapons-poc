# Vigil Ghidra Integration

This directory vendors the small Ghidra scripts used by Vigil headless analysis.
It does not vendor Ghidra itself; a full Ghidra 12.x public install is roughly
900 MB and is better installed per workstation.

## Scripts

- `VigilExportInfo.java`: program metadata, functions, imports, sections.
- `VigilListFunctions.java`: bounded function listing.
- `VigilDecompile.java`: decompile one function by name or address.
- `VigilSearchStrings.java`: printable string search.
- `VigilGetXRefs.java`: references to/from one address.

## Usage

```sh
npm run ghidra:probe
npm run ghidra:analyze -- --target C:\Windows\System32\where.exe
npm run ghidra:mcp
```

On Windows, configure or install Ghidra without admin rights:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/install-ghidra.ps1
```

Set `GHIDRA_INSTALL_DIR`, `GHIDRA_HOME`, or `VIGIL_GHIDRA_HOME` to override
auto-detection.
