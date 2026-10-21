# 运行时 DEX 与字符串分析工具

本目录说明仓库内自行编写的分析脚本。它们读取操作者提供的本地文件，或在明确指定的 Android 模拟器中提取运行时 DEX、调用字符串常量解码方法。仓库不提供 APK、DEX、Frida 二进制、反编译的 App 源码、内存转储、二维码或会话数据。

这些脚本用于解释 CHSI App 2.6.1 的可见实现。导出 DEX、得到字符串或取得公开 bootstrap 公钥，都不能证明服务端接受预拍照片完成正式采集。DEX 中的 native 方法仍然缺少可由 JADX 直接恢复的实现。

## 文件与外部工具

| 文件 | 用途 | 依赖 |
| --- | --- | --- |
| `tools/static/decode_jiagu_config.py` | 从 APK 壳 DEX 附加段恢复有边界的可打印配置记录 | Python 标准库 |
| `tools/dex/dump_proc_dex.py` | 从已运行进程的 `/proc/PID/mem` 提取普通 DEX | Python 标准库、ADB、已 root 的模拟器 shell |
| `tools/dex/dex_inventory.py` | 清点 DEX、检查头部与方法属性，按需另存头部修复副本 | Python 标准库 |
| `tools/strings/collect_ids.py` | 从本地 JADX Java 源码收集整数 `StubApp.getString2(ID)` 调用 | Python 标准库 |
| `tools/strings/decode_strings.frida16.js` | 使用 Frida 16 内置 Java bridge 调用常量解码器 | Frida 16.x |
| `tools/strings/spawn_decode_strings.py` | 暂停启动目标 App，加载短脚本，恢复后轮询解码 | ADB、Python `frida` 16.x、同版本 server |
| `tools/strings/merge_strings.py` | 合并独立解码轮次，保留已有非空值 | Python 标准库 |
| `tools/strings/annotate_sources.py` | 生成保留 ID 注释的独立源码阅读副本 | Python 标准库 |
| `tools/keys/extract_bootstrap_key.py` | 从 XML 资源和恢复的常量拼接并检查 RSA 公钥 | Python 标准库 |

原分析使用 Python 3.12、ADB、Android 7 x86_64 模拟器、JADX 1.5.6 和 Frida 16.7.19。Python 与模拟器里的 Frida server 应使用相同版本；server 的 CPU 架构须与模拟器匹配。可选的 Python 版本固定在 `tools/requirements-runtime.txt`。

外部工具由操作者另行获取：

- [Frida 官方 GitHub Releases](https://github.com/frida/frida/releases)，原分析使用 [16.7.19](https://github.com/frida/frida/releases/tag/16.7.19)。
- [JADX 官方 GitHub Releases](https://github.com/skylot/jadx/releases)，原分析使用 1.5.6。
- [Android SDK Platform Tools](https://developer.android.com/tools/releases/platform-tools)。

这些脚本不会安装 ADB、配置 root、下载 server、安装 APK或关闭模拟器网络。运行时脚本没有打开二维码、调用上传流程或替换 App 方法的代码；`spawn` 会启动原 App，其正常初始化仍会发生。离线分析应由操作者预先隔离模拟器网络，再准备原 APK 与 Frida server。

## 静态配置记录

```sh
python tools/static/decode_jiagu_config.py ./CHSI_APP_2.6.1.apk --output work/jiagu-config.json
```

输出目录应先建好。此脚本只读 ZIP 中的 `classes.dex`，验证附加段魔数，按原分析推导的有限字节替换表和记录边界恢复可打印元数据。遇到不支持的高半字节或二进制记录会停止；它不输出业务 DEX、不执行 App，也不是通用 Jiagu 解密器。输出会记录输入路径，请把本机结果留在被忽略的 `work/` 中。

## 从已运行进程提取 DEX

以下命令中的 `emulator-5554` 是示例，必须改成操作者明确选择的模拟器序列号。所有 ADB 调用均包含该序列号；脚本还要求 `ro.kernel.qemu=1`。它拒绝物理设备，要求 shell 已经是 UID 0，并核对 PID 对应的包名。

```sh
python tools/dex/dump_proc_dex.py --adb adb --serial emulator-5554 --package cn.com.chsi.chsiapp --output work/proc-dex --discard-ranges
```

此脚本只读取已经运行的进程，不启动 App。可使用 `--pid PID` 指定目标进程，仍会核对命令行；否则通过该包名查询 PID。默认每个映射最多 128 MiB，总读取上限 512 MiB，单次 ADB 命令超时最多 60 秒。`--discard-ranges` 不保存原始映射字节，保留提取的 DEX、maps、事件和错误记录。未指定它时，会在所选输出目录保存原始映射文件。

DEX 文件按原始内容的 SHA-256 命名。提取器检查普通 DEX 的文件大小、头部与主要表范围，也记录跨映射边界的候选；它不会自动重建不连续 DEX、CompactDex 或 DEX 041 容器。读取期间目标进程没有被冻结，映射可能改变。

```sh
python tools/dex/dex_inventory.py work/proc-dex --output work/dex-inventory.json
python tools/dex/dex_inventory.py work/proc-dex --output work/dex-inventory-repair.json --repair-header work/clean-dex
```

默认清点不会修改输入。`--repair-header` 另存副本，只重算 DEX 头部 SHA-1 和 Adler-32；魔数损坏时，还必须明确指定 `--magic-version` 才会改魔数。它不恢复方法体，也不把 native 或虚拟化实现转换成 Dalvik 指令。请保留原始 DEX及其哈希，再把选定的业务 DEX 一并交给 JADX。

## 使用 Frida 16 恢复字符串常量

先从本地反编译结果收集 ID。使用 `--relative-prefix` 可以只处理相关包，重复该参数可选取多个目录；不指定则扫描整个 Java 源码树。

```sh
python tools/strings/collect_ids.py --sources work/jadx/sources --relative-prefix cn/com/chsi --relative-prefix p116o3 --output work/ids.json
```

输出包括 `ids`、`priority_ids` 和每个调用的位置。通用收集器将这两个列表设为相同内容；也可以自行提供纯整数数组，或提供包含这两个列表的 JSON。每次驱动最多接收 1,000 个不同 ID，较大的集合应分批保存为独立输入文件。

在已启动匹配版本 Frida server 的模拟器上运行：

```sh
python tools/strings/spawn_decode_strings.py --adb adb --serial emulator-5554 --package cn.com.chsi.chsiapp --ids work/ids.json --output work/strings-round1.json
```

`--port` 是主机的 ADB 转发端口，`--server-port` 是模拟器内 server 端口，默认均为 27042。脚本自动建立指定模拟器的端口转发。默认 agent 就是同目录的 `decode_strings.frida16.js`；可用 `--agent` 和 `--runtime qjs|v8` 显式选择文件与引擎。驱动要求 Python Frida 主版本为 16，不会安装或切换版本。

驱动先在暂停启动的进程中加载短脚本，注册定时器，再恢复进程。脚本通过 `Java.performNow` 和显式 ClassLoader 解析 `ppaishc.ishc.moc.nc.StubApp.getString2(int)`，每 25 ms 尝试一次，总等待默认 15 秒；`--interval-ms` 允许 25–50 ms，`--wait` 不能超过 15 秒。它不显式等待原始 `Application` 初始化完成。

当前 JavaScript agent 的类名和方法名针对本项目中的加固壳。驱动的 `--package` 能选择进程包名，但不会自动适配其他加固器或其他字符串 API。脚本只调用整数常量解码器，不 hook 业务方法、不构造 Activity、不传入二维码、不改变返回值。

每 16 个成功结果会发送到主机并写盘。输出 JSON 只保存 ID 到返回字符串的映射，另生成同名 `.events.jsonl`、`.errors.json` 和 `.metadata.json`。进程退出或等待超时会保留已收到的部分结果；全部完成返回退出码 0，否则返回 2。驱动不会主动终止 App，App 自身仍可能退出。输入与输出路径由 CLI 指定，成功值不会逐条打印到终端。

JavaScript 还提供 `info`、`prepare`、`decode`、`startpoll`、`stop`、`progress` 和 `pollstatus` RPC，供其他本地驱动使用。

### 原分析中失败的 Frida 17 方案

原环境尝试过 Frida 17.24.3、独立 `frida-java-bridge` 7.0.13 与 `frida-compile` 19.1.0。bundle、展开后的纯 JavaScript 和 V8 尝试都在 `session.create_script` 附近出现 `TransportError`，而极短的原生脚本能够加载。根因没有得到确认，不能据此断定是 App 的某个反调试检查。

随后 Frida 16.7.19 的内置 Java bridge 与本仓库短脚本成功返回了选定常量。这里仅收录这条成功方案，不包含失败的 Frida 17 bundle、node_modules 或 server 二进制。原 x86_64 模拟器还缺少 App 使用的部分 ARM SDK 库，因此原始 `Application` 可能异常退出；成功提取常量不表示整个采集页面能在该模拟器运行。

## 合并与注释

单次调用没有异常，不代表返回值必然正确。原分析中，首轮有乱码或空串，后续独立轮次恢复了有效值。合并脚本按输入顺序处理：后来的非空字符串覆盖旧值；空串或 null 不覆盖已有非空字符串。它只执行这个明确规则，不猜测哪个非空字符串在语义上正确。

```sh
python tools/strings/merge_strings.py --input work/strings-round1.json work/strings-round2.json work/strings-bootstrap.json --output work/strings-merged.json --conflicts work/string-merge-log.json
python tools/strings/annotate_sources.py --sources work/jadx/sources --strings work/strings-merged.json --output work/annotated-sources
```

注释工具把已知调用替换成带原始 ID 注释的字符串表达式，只写入发生替换的文件。输出目录必须与原始源码目录分开且互不包含。该副本用于阅读，不是可直接重建 APK 的源码工程。

## 离线拼接 bootstrap 公钥

公钥提取工具不访问 bootstrap 接口。它读取本地 `strings.xml` 的 `k1` 资源，以及已恢复的字符串 ID `7662`、`7660`、`7661`，按这个顺序拼接 Base64，检查 X.509 SubjectPublicKeyInfo 中的 RSA 公钥结构并输出 JSON。

```sh
python tools/keys/extract_bootstrap_key.py --resources work/jadx/resources/res/values/strings.xml --strings work/strings-merged.json --output work/bootstrap-publickey.json
```

可用 `--resource-name` 和 `--string-ids` 调整资源名与常量拼接顺序，适配其他版本的本地分析结果。输出包含标准化 DER Base64、模数位数、指数和 DER SHA-256；终端只打印元数据。这里的公钥是 App 内 bootstrap 公钥，后续公开接口返回的服务公钥有另一个用途。取得其中任一公钥都不等同于获得用户二维码凭据，也不证明照片提交会被服务端接受。

## 本次仓库整理范围

工具文件已改为 CLI 参数或相对路径，不依赖原分析机器上的个人目录。本次整理没有安装工具、运行模拟器脚本或执行测试，也没有发出网络请求。历史运行结果用于说明兼容性边界，不作为当前环境已经复现的声明。
