# arb_inspector_next

[English](README.md)

轻量级工具，用于从高通 ELF 固件镜像（如 xbl_config.img）中提取 Anti-Rollback (ARB) 版本。同时支持 MBN 格式的基础检测

## 功能
- 解析 32/64 位 ELF 文件，定位高通 HASH 段，从 OEM 元数据读取 ARB
- 快速模式：仅输出 ARB 值（适用于脚本）
- 完整模式：显示详细的 ELF/MBN 头部信息
- MBN 格式识别与头部转储

## 用法
```
arb_inspector_next [--debug] [--quick|--full] [-v] <镜像文件>
```
- `--debug`   : 输出详细的调试信息
- `--quick`   : 仅输出 ARB 版本（默认）
- `--full`    : 输出完整的镜像信息
- `-v`        : 显示版本并退出

## 构建
```bash
cargo build --release
```

## 许可证
MIT 详见 [LICENSE](LICENSE)