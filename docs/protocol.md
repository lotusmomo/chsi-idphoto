# 上传协议

本文记录从 CHSI Android 2.6.1 提取的请求结构，以及独立 Python 客户端已经验证的上传路径。它不是服务方发布的 API 文档。不同采集任务、服务端版本和签名策略可能不同。

请求示例均使用占位符。二维码内容、JWT、OSS 临时凭据、对象地址和照片不应写入公开文档或提交到 Git。

## 正常调用顺序

业务 API 基址为 `https://appapi.chsi.com.cn/idphoto/v1/`。以下接口均使用 POST。

| 步骤 | 地址 | 加密前的业务参数 | 作用 |
| --- | --- | --- | --- |
| 1 | `https://account.chsi.com.cn/passport/d1/device` | `appId`、`deviceInfo`；另一路客户端还传版本和设备类型信息 | 初始化安装实例，取得业务公钥 |
| 2 | `/check` | `issueId`，可选 `uid` | 消费二维码，取得 `jwt` 和 `captureId` |
| 3 | `/capture/osssign` | `issueId`、`captureId`、`bgColor` | 取得本次 OSS 上传授权 |
| 4 | 签名响应的 `host` | multipart 表单和照片文件 | 将照片字节上传到 OSS |
| 5 | `/capture/ossrs` | `issueId`、`captureId`、`bgColor`、`stsId`、`eTag` | 把实际 OSS 回执交给采集服务 |
| 6 | `/capture/checkst` | `issueId`、`captureId` | 查询服务端照片处理和可执行操作 |
| 7 | `/capture/confirm` | `issueId`、`captureId` | 在服务端允许时确认采集照片 |

第 2 步的 Java 请求没有 `Authorization`，`uid` 也不是无条件必填。后续业务请求将第 2 步返回的 `jwt` 原样放入 `Authorization`，不能自行添加 `Bearer ` 前缀。不同任务是否另有账号条件，由服务端决定。

`requests.Session` 保留初始化和业务请求产生的 Cookie。OSS 上传使用独立会话，避免把业务 JWT 或 Cookie 带到对象存储。

### 二维码参数

深链形式为 `chesicc://idphoto/<opaque-token>`。客户端把主机名后面的完整路径内容作为 `issueId`；不能按路径中的 `/` 再拆字段，也不能把 `+` 当作表单空格。URL 百分号转义需要解码，令牌内部结构保持不变。

`check` 返回的 `data` 至少需要非空 `jwt` 和 `captureId`。它还可能提供 `tip`、`bgtip`、`exitTip` 和背景选项数组 `bg`。

## 初始化与加密封装

### 安装标识和公钥

Android 的安装标识由随机 UUID 去掉连字符后生成，并在本地保存。设备初始化接口把这个值叫作 `appId`，业务封装把同一个值叫作 `did`。它不是 APK 包名，也不是二维码中的用户标识。

初始化存在不依赖已有业务公钥的路径。`p188x3.a.c` 发送：

```json
{
  "appId": "<installation-id>",
  "deviceInfo": {
    "width": 1080,
    "height": 1920,
    "manufacturer": "<manufacturer>",
    "product": "<product>",
    "brand": "<brand>",
    "model": "<model>",
    "board": "<board>",
    "device": "<device>",
    "sdk": 24,
    "release": "<android-release>"
  }
}
```

上例描述解密后的字段结构；实际发送的是下面的 `k/d` 密文封装。尺寸和设备值只是结构示例，不是服务端规定值。

APK 内置的 bootstrap RSA 公钥由字符串资源 `k1` 与受保护字符串片段拼接组成。资源 ID 为 `0x7f1000f3`，拼接关系见 `p044f3.o.a`、`p044f3.m.a`、`p044f3.n.a`。该公钥用于初始化请求和初始化响应恢复；初始化返回的 `publicKey` 才用于照片业务请求。

### 请求密文

每次请求生成新的 32 字节 ASCII 会话密钥：随机 UUID 去掉连字符后的文本字节。它直接作为 AES 密钥使用。

| 项目 | 算法或编码 |
| --- | --- |
| 参数序列化 | 紧凑 UTF-8 JSON |
| 对称加密 | AES-256-CBC，16 字节分组 |
| 填充 | Java `PKCS5Padding`；对 AES 等价于 Python 的 PKCS7 分组填充 |
| 固定 IV | ASCII `A-16-Byte-String` |
| 密钥封装 | RSA / PKCS#1 v1.5 加密 |
| Base64 | Android `Base64.DEFAULT`，每 76 字符换行并带末尾换行 |

令 `S` 为本次会话密钥、`P` 为相应 RSA 公钥：

```text
d = Base64(AES-CBC-PKCS7(UTF8(JSON(业务参数)), S, IV))
k = Base64(RSA-PKCS1v1.5-encrypt(P, UTF8(Base64(S))))
```

初始化请求直接发送 JSON `{"k": k, "d": d}`，不对这两个字符串做 URL 编码。

照片业务请求发送以下外层 JSON；`k` 和 `d` 分别按 Android `Uri.encode` 做百分号编码。这里仍是 JSON 请求，不是 `application/x-www-form-urlencoded` 表单。

```json
{
  "did": "<installation-id>",
  "v": "v1",
  "k": "<percent-encoded-base64>",
  "d": "<percent-encoded-base64>"
}
```

### 初始化响应恢复

初始化接口正常分支返回 `code` 为 `000000` 或 `000008`。将 `data` 解析为包含 `k`、`d` 的对象，然后：

1. Base64 解码响应 `k`，使用 bootstrap 公钥做 RSA 公钥恢复。
2. 严格验证恢复结果的 PKCS#1 v1.5 type 1 填充：`00 01 FF…FF 00 payload`。
3. Base64 解码 `payload`，得到一个仍以 Base64 表示的 AES 密钥字符串。
4. 再做一次 Base64 解码，得到实际 AES 密钥字节。
5. Base64 解码响应 `d`，使用该密钥和固定 IV 解密、去填充，再解析 JSON 的 `publicKey`。

RSA 公钥恢复不等同于调用普通的私钥解密 API。漏掉第 4 步会把 44 字节的 Base64 文本当成 AES 密钥，导致无效密钥长度错误。

Android 的 `p044f3.o.e` 保存初始化的加密响应对象；`o.b` 在需要时重新恢复其中的业务公钥。独立客户端可以维护自己的安装标识和公钥缓存，但不能假设服务端公钥永不轮换。

## OSS 上传

`capture/osssign` 的 `data` 包含本次授权信息，包括：

`stsId`、`host`、`objectKey`、`policy`、`xOssCredential`、`xOssDate`、`signature`、`securityToken`、`version`、`expiration`、`successActionStatus`，以及可能出现的 `bucketName`、`origin`。

上传前必须验证必需字段并保存恢复状态。不能生成或替换服务端签名、固定对象键，也不能使用过期授权。

### multipart 字段

| 表单字段 | 来源 |
| --- | --- |
| `key` | `objectKey` |
| `OSSAccessKeyId` | `xOssCredential` 第一个 `/` 之前的部分 |
| `x-oss-credential` | `xOssCredential` |
| `policy` | `policy` |
| `x-oss-signature` | `signature` |
| `Signature` | 同一个 `signature`；APK 同时传这两个字段 |
| `x-oss-security-token` | `securityToken` |
| `x-oss-date` | `xOssDate` |
| `x-oss-signature-version` | `version` |
| `success_action_status` | `successActionStatus` |
| `file` | 照片字节，MIME 为 `image/jpeg`，文件名取 `objectKey` 的最后一段 |

由 HTTP 库生成 multipart boundary；不要手写整个请求的 `Content-Type`。签名中有 `origin` 时可传入 `Origin` 请求头，现有证据不足以把某个固定 Origin 写成所有任务的必填值。

实测服务端曾返回 HTTP 形式的 OSS host。客户端将相同主机和路径升级为 HTTPS 后上传；未修改对象键、policy 或签名字段。这个兼容处理不代表所有自定义 OSS 地址都保证有相同的 TLS 服务。

### policy 的范围

已验证任务的 Base64 policy 解码后，包含固定对象键条件与文件长度范围。去除真实值后的相关条件形如：

```json
[
  ["eq", "$key", "<server-object-key>"],
  ["content-length-range", 1024, 1048576]
]
```

这说明该次授权要求精确对象键，照片文件大小范围为 1 KiB 至 1 MiB。它是已观察到的上传授权条件，不是所有任务、所有版本的全局限制。后续应解析每次服务器返回的 policy。

policy 的文件长度限制不包括服务端照片业务的全部审核规则，也不能用它推导最大像素尺寸、支持的全部图片格式或人像合规标准。

### ETag 与回执

只使用 OSS 实际返回的 ETag：先读 HTTP `ETag` 响应头；HTTP 201 时也可从 XML 响应体读取。移除外层引号，不自行用文件 MD5 替代。

提交给 `capture/ossrs` 的字段名是 **`eTag`**，大小写必须保留。正常回执包含正数 `timeout`、`interval` 和可选 `tip`；Android 在该路径拒绝无效的超时和间隔。

## 轮询、确认和网页选用

`capture/checkst` 的业务响应可能包含：

`status`、`photo`、`qualityStatus`、`qualityStatusDesc`、`qualityError`、`qualityTip`、`confirmPhoto`、`selectBackground`、`reCapture`、`message`、`confirmPhotoTip`。

已恢复的轮询器对 `PROCESSING` 继续等待，正常成功响应后通常间隔 3 秒；`QUALITY_CHECKING` 会把结果交给照片预览和质检界面。`EXP` 是异常分支，`reCapture` 决定是否允许重拍。未知状态不能自动判为成功。

`QUALITY_CHECKING` 本身不表示照片已经通过所有审核或已经被用户确认。独立客户端仅在用户明确选择确认，且服务器返回 `confirmPhoto=1` 时调用 `capture/confirm`。

以下结果应分别报告：

- `storage_uploaded`：OSS 接收了照片字节并返回可用 ETag。
- `receipt_accepted`：采集服务接受了 OSS 回执，返回有效处理参数。
- `server_status`：服务器实际返回的照片处理信息。
- `confirmed`：照片确认接口返回成功。

**`capture/confirm` 确认的是采集任务照片。它不等于在报名网页点击“用作报名照片”。** 报名系统中的照片预览、选择和最终业务提交属于另一层流程，本工具没有实现该网页操作。

## 一次性二维码与故障恢复

实测二维码会在成功 `check` 后变为已使用。签名失败、上传中断或程序退出后，不应再次调用同一个二维码的 `check`。

客户端恢复流程需要：

1. 发请求前确认状态目录可写，保存安装标识、二维码摘要、照片摘要和背景选择。
2. 在发送 `check` 前写入 `check_pending`。
3. `check` 成功后立即保存 JWT 和 `captureId`，再请求签名。
4. 在上传前保存签名和授权对象，上传成功后保存 ETag 与 `stsId`。
5. 分别保存回执、处理状态和确认结果；恢复时跳过已经有可靠结果的步骤。

若只有 `check_pending` 而没有可靠响应，程序无法判断服务器是否已消费二维码，应停止自动重发并要求刷新二维码。保存了 `check` 结果的任务则继续使用原 JWT 和 `captureId`，不再扫码。

网络响应和本地写盘不属于同一事务。进程在两者之间退出时仍可能留下结果不确定的窗口；本地检查点不能提供服务端的“恰好执行一次”保证。不要把超时直接解释为服务器没有接收到请求。

会话文件含可继续操作采集任务的凭据，只保存在本机。文件摘要仅用于恢复时确认照片未变，不应随公开报告或示例一起发布。

## 其他已识别接口

以下接口不属于最小上传路径：

| 地址 | 加密前参数 | 已知用途 |
| --- | --- | --- |
| `/capture/confirmbg` | `issueId`、`captureId`、`bgColor` | 处理后确认背景选择，再进入状态轮询 |
| `/capture/recap` | `issueId`、`captureId` | 请求重新采集，成功时返回新的 `captureId` |
| `/capture/cancel` | `issueId`、`captureId` | 取消采集 |
| `/capture/event` | `issueId`、`captureId`、`eventType`、`code`、`result`、`msg`，特定事件另有 `stsId` | 采集阶段事件记录 |

静态封装不能证明所有事件上报都是服务端必须的状态转换。导入预拍照片的客户端不应伪造“已完成相机或眨眼检测”的事件。

## 证据定位

| 内容 | Java 类与方法 |
| --- | --- |
| 设备初始化与公钥保存 | `p188x3.a.c`、`V2.j.l/e`、`p044f3.o.a/b/e` |
| AES 与 RSA 编码 | `p044f3.a.c/d/e/f`、`p044f3.u.a/b/d/e/f` |
| 业务请求封装 | `p116o3.B.F` |
| check / 签名 / 回执 / 轮询 / 确认 | `p116o3.B.w/H/G/x/y` |
| OSS 表单和回执解析 | `p116o3.B.J/t`、`p068i3.a.l/I` |
| 超时与轮询状态 | `p116o3.g.o` |
| 采集回调中的 ETag 与回执检查 | `CaptureIdPhotoActivity.z3/y3/v2` |

研究对象的 APK 标识和完整验证边界见 [分析结论](findings.md)。本仓库不包含反编译源代码、运行时 DEX 或 APK。
