# arb_inspector_next

[中文版](README_zh.md)

A lightweight tool to extract Anti-Rollback (ARB) version from Qualcomm ELF firmware images (e.g., xbl_config.img). Also supports basic MBN inspection.

## Features
- Parse 32/64‑bit ELF files, locate Qualcomm HASH segment, and read ARB from OEM metadata.
- Quick mode: output only ARB value (for scripting).
- Full mode: display detailed ELF/MBN header information.
- MBN format detection and header dump.

## Usage
```
arb_inspector_next [--debug] [--quick|--full] [-v] <image>
```
- `--debug`   : enable verbose debug output
- `--quick`   : output only ARB version (default)
- `--full`    : output complete image information
- `-v`        : show version and exit

## Build
```bash
cargo build --release
```

## License
MIT See [LICENSE](LICENSE)