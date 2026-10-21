# 提交到 GitHub

建议仓库名：`chsi-idphoto`。本地以 `main` 为主分支。

在 GitHub 创建一个空仓库，不勾选自动生成 README、许可证或 `.gitignore`，然后在本仓库目录执行：

```shell
git remote add origin https://github.com/OWNER/chsi-idphoto.git
git push -u origin main
```

将 `OWNER` 替换为目标账户或组织。仓库可见性由创建者选择。也可在 GitHub CLI 中指定目标后创建并推送：

```shell
gh repo create OWNER/chsi-idphoto --private --source=. --remote=origin --push
```

若已有 `origin`，用 `git remote set-url origin <目标仓库URL>` 更新，不要重复添加。

## 已整理的发布内容

- 客户端和运行时辅助脚本。
- 协议、分析经过、验证边界和工具使用说明。
- 脱敏响应结构、公开公钥和 APK/DEX 哈希元数据。

原始二维码、任务 JWT、OSS STS/签名、真实桶内对象路径、照片、截图、照片哈希、ETag、运行报告和个人机器路径不随仓库提交。客户端代码中的 `BOOTSTRAP_KEY_B64` 是 APK 内置 **RSA 公钥**，不是私钥或访问凭据。

`.gitignore` 已覆盖默认状态文件、报告、图片和 APK/DEX 等本地产物。不要使用 `git add -f` 将这些文件强行加入历史；自定义输出路径时，也应把对应路径加入忽略规则。

MIT 许可证仅覆盖项目自行编写的代码和文档，第三方 App 及依赖的范围见 [NOTICE](../NOTICE.md)。
