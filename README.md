# ECH 部署探测工具

复现论文 *"Towards a Complete View of Encrypted Client Hello Deployments"*（SIGCOMM 2025）的测量方法。

## 工作原理

```
测量节点                                    目标服务器
  │                                              │
  │──① ClientHello [sni:target, ech:随机垃圾]──▶│
  │                                              │  无法解密 ECH
  │◀──② HelloRetryRequest [ech_configs:真实配置]─│  必须返回真实 key
  │                                              │
  │──③ ClientHello [sni:public-name, ech:加密]──▶│  用真实公钥加密
  │◀──④ ServerHello（握手完成）──────────────────│
  │                                              │
  │──⑤ 普通 TLS 握手（无 ECH，对比延迟）──────▶ │
```

关键点：步骤 ① 故意发送无效 ECH，使服务端无法解密，从而强制触发 HelloRetryRequest。
这意味着**即使服务端不在 DNS 中发布 ECH 配置**（如 Meta），也能被发现。

## 文件结构

```
.github/
  workflows/
    ech-probe.yml       # GitHub Actions 工作流
scripts/
  probe_ech.py          # 核心探测脚本
```

## 本地运行

```bash
# 1. 编译 OpenSSL ECH 分支
git clone --depth=1 --branch feature/ech \
  https://github.com/openssl/openssl.git
cd openssl
./Configure --prefix=$PWD/../openssl-ech no-shared linux-x86_64
make -j$(nproc) && make install_sw
cd ..

# 2. 安装 Python 依赖
pip install aiofiles dnspython

# 3. 准备域名文件
echo -e "cloudflare.com\nfacebook.com\ngoogle.com" > domains.txt

# 4. 运行探测
python scripts/probe_ech.py \
  --domains domains.txt \
  --openssl ./openssl-ech/bin/openssl \
  --concurrency 20 \
  --timeout 5 \
  --output results/
```

## 通过 GitHub Actions 运行

### 手动触发

1. 进入仓库 → Actions → **ECH Deployment Probe** → Run workflow
2. 可选填写自定义域名（逗号分隔）或留空使用内置样本

### 定时运行

工作流默认每天 UTC 02:00 自动运行，结果作为 Artifacts 保留 30 天。

## 输出

| 文件 | 内容 |
|------|------|
| `results/results.json` | 每个域名的完整探测数据 |
| `results/results.csv`  | 同上，CSV 格式，便于分析 |
| `results/summary.txt`  | 文字摘要（各 public_name 域名数、延迟统计）|

### 结果字段说明

| 字段 | 含义 |
|------|------|
| `supports_ech` | 服务器是否支持 ECH |
| `hrr_received` | 是否收到 HelloRetryRequest |
| `ech_public_name` | 服务器广播的公开名（如 `cloudflare-ech.com`）|
| `ech_config_b64` | 服务器返回的第一个 ECHConfig（base64）|
| `validation_ok` | 用真实配置握手是否成功 |
| `latency_ech_ms` | ECH 握手耗时（ms）|
| `latency_plain_ms` | 普通 TLS 握手耗时（ms）|
| `latency_delta_ms` | ECH 额外延迟 = ech - plain（ms）|

## 说明

- 本工具仅探测服务器**是否支持 ECH**，不解密任何 ECH 内容
- ECH 的加密使用服务器公钥（非对称），无私钥无法解密
- 测量方法利用 ECH 协议本身的标准行为，不涉及漏洞利用
- 用途：网络测量研究、ECH 部署统计
