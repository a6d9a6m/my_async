# Make 目标 (命令)
可以要求 make 执行的操作：
```textmate
all: 这是默认目标 。它会执行 build 目标 。
build: 编译源代码并创建最终的可启动镜像（.bin 或 .uimg 文件） 。
run: 首先，它会构建项目（与 make build 相同），然后在 QEMU 中执行应用程序 (justrun) 。
justrun: 在 QEMU 中执行已构建的应用程序 。
debug: 构建项目，然后在调试模式下启动 QEMU，等待 GDB 在 localhost:1234 上连接 。它还会尝试自动连接 GDB，在 rust_entry 处设置断点，继续执行，并显示反汇编指令 。
disasm: 使用 rust-objdump 显示输出的 ELF 文件的反汇编代码 。
defconfig: 为项目生成默认配置文件 。
oldconfig: 根据当前设置更新现有配置文件 。
clippy: 运行 cargo clippy，这是一个 Rust 代码的 linter (代码检查工具)，用于检查潜在错误和风格问题 。
doc: 使用 cargo doc 为 Rust crates (包) 生成文档 。
doc_check_missing: 同样生成文档，可能用于检查所有公共 API 是否都有文档 。
fmt: 使用 cargo fmt 格式化 Rust 代码 。
fmt_c: 使用 clang-format 格式化 C 代码 。
unittest: 运行单元测试 。
unittest_no_fail_fast: 运行单元测试，并且在第一个测试失败时不会立即停止 。
disk_img: 如果磁盘镜像 (DISK_IMG 指定的文件) 不存在，则创建一个 。
clean: 清理大部分构建产物，例如 .bin 和 .elf 文件以及配置文件 。
clean_c: 清理 C 语言相关的构建产物 。
```
# 可配置变量 (选项)
可以在执行 make 时在命令行中设置的变量 (例如 make ARCH=riscv64 SMP=2)，或者直接在 Makefile 中修改它们的默认值。它们用于控制构建过程和 QEMU 虚拟机的行为。

常规选项
```textmate
ARCH: 目标CPU架构：可选值为 x86_64, riscv64, aarch64 。默认值: x86_64。
PLATFORM: 目标平台，对应 platforms 目录中的某个平台 。
SMP: CPU 核心数量 。默认值: 1。
MODE: 构建模式：release (发行版) 或 debug (调试版) 。默认值: release。
LOG: 日志级别：warn, error, info, debug, trace 。默认值: warn。
V: 详细输出级别：空值 (不详细)，1, 或 2 (更详细) 。
TARGET_DIR: 构建产物输出目录 (cargo 的目标目录) 。默认值: $(PWD)/target (当前工作目录下的 target 文件夹) 。

EXTRA_CONFIG: 额外的配置文件路径 。
OUT_CONFIG: 最终生效的配置文件路径 。默认值: $(PWD)/.axconfig.toml (当前工作目录下的 .axconfig.toml 文件) 。

UIMAGE: 是否生成 U-Boot 格式的镜像 。默认值: n (否)。
应用选项
A 或 APP: 应用程序的路径 。APP 的值默认等于 A 的值 。A 的默认值: examples/helloworld。
FEATURES: 需要启用的 ArceOS 模块的特性 。
APP_FEATURES: 需要启用的 (Rust) 应用程序的特性 。
QEMU 选项
BLK: 是否启用存储设备 (virtio-blk) 。默认值: n (否)。
NET: 是否启用网络设备 (virtio-net) 。默认值: n (否)。
GRAPHIC: 是否启用显示设备和图形输出 (virtio-gpu) 。默认值: n (否)。
BUS: 设备总线类型：mmio 或 pci 。默认值: pci。
MEM: QEMU 虚拟机的内存大小 。默认值: 128M。
DISK_IMG: 虚拟磁盘镜像的路径 。默认值: disk.img。
ACCEL: 是否启用硬件加速 (例如 Linux 上的 KVM) 。
QEMU_LOG: 是否启用 QEMU 日志记录 (日志文件为 "qemu.log") 。默认值: n (否)。
NET_DUMP: 是否启用网络数据包转储 (日志文件为 "netdump.pcap") 。默认值: n (否)。
NET_DEV: QEMU 网络设备后端类型：user (用户模式网络), tap (TAP设备), bridge (网桥) 。默认值: user。
VFIO_PCI: 要透传给虚拟机的 PCI 设备地址，格式为 "bus:dev.func" 。
VHOST: 是否为 tap 后端启用 vhost-net (仅当 NET_DEV=tap 时有效) 。默认值: n (否)。
```
# 网络选项

这些通常用于配置虚拟机内部的网络环境：

IP: ArceOS 的 IPv4 地址 (当 QEMU 使用 user netdev 时默认为 10.0.2.15) 。默认值: 10.0.2.15。

GW: 网关 IPv4 地址 (当 QEMU 使用 user netdev 时默认为 10.0.2.2) 。默认值: 10.0.2.2。