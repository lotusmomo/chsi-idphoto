# 脱敏样例

- `upload-result.redacted.json`：真实成功响应的精简结构，删除照片、摘要、ETag 和任务身份。
- `oss-policy.redacted.json`：实际观察到的 policy 条件，保留 1 KiB～1 MiB 范围和 key 精确匹配语义，移除桶名、凭证和对象路径。

`<redacted>` 为占位符。样例不包含可用二维码、JWT、签名或有效期，不能用于上传。
