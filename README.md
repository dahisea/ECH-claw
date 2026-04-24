# ECH Scanner

> **Encrypted Client Hello (ECH) 部署探测工具**  
> 基于 TLS 1.3 HelloRetryRequest 机制，零依赖，纯 Go 实现。

[![ECH Scanner](https://github.com/your-username/ech-scanner/actions/workflows/ech-scan.yml/badge.svg)](https://github.com/your-username/ech-scanner/actions/workflows/ech-scan.yml)

---

## 工作原理

```
客户端                           服务器
   │                               │
   │── ClientHello (无效 ECH) ───►│   ← config_id=0xFF，服务器无法解密
   │                               │
   │◄── HelloRetryRequest ─────────│   ← 规范要求附带真实 retry_configs
   │      + ECH retry_configs      │
   │                               │
   解析 ECHConfigList，提取 public_name / ECHConfig
```

探测依据：[draft-ietf-tls-esni-24 §6.1.6](https://datatracker.ietf.org/doc/draft-ietf-tls-esni/)  
支持 ECH 的服务器**必须**在 HRR 的 ECH 扩展中返回 `retry_configs`，本工具正是通过此机制判断服务器是否部署了 ECH。

---

## 快速开始

### 本地运行

```bash
git clone https://github.com/your-username/ech-scanner
cd ech-scanner

# 编译
go build -o probe_ech ./probe_ech.go

# 扫描默认域名列表
./probe_ech --domains domains.txt

# 自定义参数
./probe_ech \
  --domains domains.txt \
  --concurrency 50 \
  --timeout 10 \
  --output ./my-results/
```

### 参数说明

| 参数 | 默认值 | 说明 |
|---|---|---|
| `--domains` | **必填** | 域名列表文件路径 |
| `--concurrency` | `20` | 最大并发探测数 |
| `--timeout` | `5.0` | 每个域名的超时（秒） |
| `--output` | `results/` | 结果输出目录 |
| `--openssl` | `openssl` | ECH 分支 openssl 路径（可选，用于握手验证） |

### 域名列表格式

```
# 注释行（忽略）
cloudflare.com
facebook.com
github.com
```

---

## GitHub Actions

### 触发方式

| 方式 | 说明 |
|---|---|
| **定时（每天 UTC 02:00）** | 自动扫描，结果推送到 `results` 分支 |
| **手动 workflow_dispatch** | 在 Actions 页面手动触发，可自定义参数 |
| **push / PR** | 修改 `domains.txt` 或代码时自动触发冒烟测试 |

### 手动触发参数

在 Actions → ECH Scanner → Run workflow 中可配置：

- `domains_file`：域名列表文件（默认 `domains.txt`）
- `concurrency`：并发数（默认 30）
- `timeout`：超时秒数（默认 8）

### 结果存储

- **Artifacts**：每次运行自动上传，保留 90 天
- **results 分支**：定时 / push / 手动触发时自动推送，长期存档

### Step Summary 示例

每次运行后，Actions 的 Summary 页面会显示：

```
# 🔒 ECH 扫描结果

| 指标 | 值 |
|---|---|
| 总域名 | 50 |
| ✅ 支持 ECH | 12 (24.0%) |
| 握手验证通过 | 0 |
| ❌ 连接失败 | 3 |

## 📊 public_name 分布

| public_name | 域名数 |
|---|---|
| cloudflare-ech.com | 8 |
| ...                | ... |
```

---

## 输出文件

| 文件 | 说明 |
|---|---|
| `results/results.json` | 完整探测结果（JSON 数组） |
| `results/results.csv` | 完整探测结果（CSV） |
| `results/summary.txt` | 统计摘要（纯文本） |

### JSON 字段说明

```jsonc
{
  "domain": "cloudflare.com",
  "supports_ech": true,           // 是否支持 ECH
  "ech_public_name": "cloudflare-ech.com",  // ECHConfig 中的 public_name
  "ech_config_b64": "AEX+DQ...", // ECHConfigList base64（可直接传给 openssl）
  "hrr_received": true,           // 是否收到 HelloRetryRequest
  "validation_ok": null,          // openssl 握手验证结果（需要 ECH openssl）
  "latency_ech_ms": null,         // ECH 握手延迟 ms
  "latency_plain_ms": null,       // 普通握手延迟 ms
  "latency_delta_ms": null,       // ECH 额外延迟 ms
  "error": null                   // 连接/解析错误信息
}
```

---

## 使用 openssl 验证（可选）

如需握手验证和延迟测量，需要编译支持 ECH 的 OpenSSL：

```bash
# 编译 ECH 分支 openssl（约需 5 分钟）
git clone https://github.com/sftcd/openssl -b ECH-draft-13c
cd openssl
./config --prefix=$HOME/openssl-ech
make -j$(nproc)
make install

# 使用
./probe_ech --domains domains.txt --openssl $HOME/openssl-ech/bin/openssl
```

---

## 本地快速测试

```bash
# 只测 3 个域名
echo -e "cloudflare.com\nfacebook.com\ngithub.com" > test_domains.txt
./probe_ech --domains test_domains.txt --concurrency 3 --timeout 10
```

---

## 许可证

MIT
