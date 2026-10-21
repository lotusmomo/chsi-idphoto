# 代码与资料来源

本项目包含自行编写的 Python/Frida 工具和分析文档，以 [MIT License](LICENSE) 提供。

分析对象为 `CHSI_APP_2.6.1.apk`，包名 `cn.com.chsi.chsiapp`。本项目不属于学信网、研招网或阿里云官方项目。

客户端内的 bootstrap RSA **公钥**和协议常量来自该 APK，用于复现请求封装；它们不是私钥、用户登录凭据或临时 OSS 上传凭据。APK、运行时 DEX、App 的完整反编译源码、图标和其他原始资源没有包含在仓库中，它们的权利归原权利人所有。

运行时依赖 `requests`、`cryptography` 和可选的 `frida`，分别遵循其上游许可证。Android SDK、JADX、Frida server 由使用者从各自官方来源获取，不随仓库分发。
