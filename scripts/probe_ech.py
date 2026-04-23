#!/usr/bin/env python3
"""
probe_ech.py — 复现论文方法的 ECH 部署探测器

原理：向目标发送含随机加密 ECH 扩展的 ClientHello。
     若服务器支持 ECH，必须按 RFC 返回 HelloRetryRequest，
     其中包含真实的 ECH 配置（公钥 + 公开名）。
     再用该配置发起正式 ECH 握手完成验证，并测量延迟。
"""

import argparse
import asyncio
import base64
import csv
import json
import os
import socket
import ssl
import struct
import subprocess
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Optional

# ── TLS 常量 ────────────────────────────────────────────────────────────────

TLS_RECORD_HANDSHAKE    = 0x16
TLS_HANDSHAKE_CLIENT_HELLO = 0x01
TLS_HANDSHAKE_SERVER_HELLO = 0x02
TLS_EXT_ECH             = 0xFE0D   # draft-ietf-tls-esni-24
TLS_EXT_SNI             = 0x0000
TLS_EXT_SUPPORTED_VERSIONS = 0x002B
TLS_EXT_KEY_SHARE       = 0x0033
TLS_VERSION_TLS12       = 0x0303   # TLS record layer 版本字段（固定）
TLS_VERSION_TLS13       = 0x0304


# ── 数据结构 ─────────────────────────────────────────────────────────────────

@dataclass
class ProbeResult:
    domain: str
    supports_ech: bool = False
    ech_public_name: Optional[str] = None
    ech_config_b64: Optional[str] = None   # 服务器返回的第一个 ECHConfig
    hrr_received: bool = False             # 是否收到 HelloRetryRequest
    validation_ok: bool = False            # 用真实配置握手是否成功
    latency_ech_ms: Optional[float] = None
    latency_plain_ms: Optional[float] = None
    latency_delta_ms: Optional[float] = None
    error: Optional[str] = None


# ── 构造伪造 ECH 扩展的 ClientHello ─────────────────────────────────────────

def _ext(ext_type: int, data: bytes) -> bytes:
    return struct.pack("!HH", ext_type, len(data)) + data

def _vec16(data: bytes) -> bytes:
    return struct.pack("!H", len(data)) + data

def _vec8(data: bytes) -> bytes:
    return struct.pack("!B", len(data)) + data

def build_client_hello(sni: str, ech_data: Optional[bytes] = None) -> bytes:
    """
    构造最简 TLS 1.3 ClientHello。
    ech_data=None → 普通握手；
    ech_data=b"random" → 伪 ECH（触发 HRR）；
    ech_data=<real> → 真实 ECH 握手（需由 openssl 命令完成，见下文）
    """
    # SNI 扩展
    sni_bytes = sni.encode()
    sni_ext = _ext(TLS_EXT_SNI,
        _vec16(struct.pack("!BH", 0, len(sni_bytes)) + sni_bytes))

    # supported_versions: TLS 1.3
    sv_ext = _ext(TLS_EXT_SUPPORTED_VERSIONS,
        _vec8(struct.pack("!H", TLS_VERSION_TLS13)))

    # key_share: x25519 占位（32 字节随机）
    key_share_entry = struct.pack("!H", 0x001D) + _vec16(os.urandom(32))
    ks_ext = _ext(TLS_EXT_KEY_SHARE, _vec16(key_share_entry))

    extensions = sni_ext + sv_ext + ks_ext

    if ech_data is not None:
        # outer_type=0 (ClientHelloOuter), 附加随机 ECH payload
        # 格式: type(1) + cipher_suite(4) + config_id(1) + enc(vec16) + payload(vec16)
        # 我们故意用全零/随机使服务端无法解密，从而触发 HRR
        fake_ech = (
            b"\x00"              # outer type
            b"\x00\x01\x00\x01" # HPKE: DHKEM(X25519)+HKDF-SHA256+AES-128-GCM (any)
            + b"\x00"            # config_id = 0 (不存在)
            + _vec16(os.urandom(32))   # enc (随机)
            + _vec16(os.urandom(64))   # payload (随机垃圾)
        )
        extensions += _ext(TLS_EXT_ECH, fake_ech)

    # random (32 bytes) + session_id (0) + cipher_suites + compression
    hello_body = (
        os.urandom(32)                      # random
        + b"\x00"                           # session_id len = 0
        + _vec16(b"\x13\x01\x13\x02\x13\x03")  # TLS_AES_{128,256}_GCM + CHACHA
        + b"\x01\x00"                       # compression: null only
        + _vec16(extensions)
    )

    handshake = (
        struct.pack("!B", TLS_HANDSHAKE_CLIENT_HELLO)
        + struct.pack("!I", len(hello_body))[1:]   # 3-byte length
        + hello_body
    )

    record = (
        struct.pack("!BHH", TLS_RECORD_HANDSHAKE, TLS_VERSION_TLS12, len(handshake))
        + handshake
    )
    return record


# ── 解析服务端响应，查找 HelloRetryRequest 中的 ECH 配置 ────────────────────

def parse_hrr_ech_configs(data: bytes) -> Optional[list[dict]]:
    """
    从服务端返回的原始字节中提取 ECHConfig 列表。
    返回 [{"public_name": str, "raw_b64": str}, ...]  或 None。

    HelloRetryRequest 在 TLS 1.3 中表现为 ServerHello，
    其 random 字段固定为 "HelloRetryRequest" 的 SHA-256：
      CF 21 AD 74 E5 9A 61 11 BE 1D 8C 02 1E 65 B8 91
      C2 A2 11 16 7A BB 8C 5E 07 9E 09 E2 C8 A8 33 9C
    """
    HRR_MAGIC = bytes([
        0xCF,0x21,0xAD,0x74,0xE5,0x9A,0x61,0x11,
        0xBE,0x1D,0x8C,0x02,0x1E,0x65,0xB8,0x91,
        0xC2,0xA2,0x11,0x16,0x7A,0xBB,0x8C,0x5E,
        0x07,0x9E,0x09,0xE2,0xC8,0xA8,0x33,0x9C,
    ])

    pos = 0
    while pos + 5 <= len(data):
        rec_type = data[pos]
        # rec_ver  = data[pos+1:pos+3]  # not needed
        rec_len  = struct.unpack("!H", data[pos+3:pos+5])[0]
        pos += 5
        if pos + rec_len > len(data):
            break
        payload = data[pos:pos+rec_len]
        pos += rec_len

        if rec_type != TLS_RECORD_HANDSHAKE:
            continue

        hs_pos = 0
        while hs_pos + 4 <= len(payload):
            hs_type = payload[hs_pos]
            hs_len  = struct.unpack("!I", b"\x00" + payload[hs_pos+1:hs_pos+4])[0]
            hs_pos += 4
            if hs_pos + hs_len > len(payload):
                break
            hs_body = payload[hs_pos:hs_pos+hs_len]
            hs_pos += hs_len

            # ServerHello (0x02) の random を確認
            if hs_type == TLS_HANDSHAKE_SERVER_HELLO and len(hs_body) >= 34:
                srv_random = hs_body[2:34]
                if srv_random != HRR_MAGIC:
                    continue  # 不是 HRR，跳过

                # 是 HRR — 解析扩展寻找 ECH retry_configs
                ext_start = 34  # version(2) + random(32)
                # skip session_id
                if ext_start >= len(hs_body):
                    continue
                sid_len = hs_body[ext_start]
                ext_start += 1 + sid_len
                # skip cipher suite + compression
                ext_start += 3
                if ext_start + 2 > len(hs_body):
                    continue
                exts_len = struct.unpack("!H", hs_body[ext_start:ext_start+2])[0]
                ext_start += 2
                exts_end = ext_start + exts_len
                results = []

                ep = ext_start
                while ep + 4 <= exts_end:
                    e_type = struct.unpack("!H", hs_body[ep:ep+2])[0]
                    e_len  = struct.unpack("!H", hs_body[ep+2:ep+4])[0]
                    ep += 4
                    e_data = hs_body[ep:ep+e_len]
                    ep += e_len

                    if e_type == TLS_EXT_ECH:
                        # retry_configs: ECHConfigList (vec16 of ECHConfig)
                        configs = _parse_ech_config_list(e_data)
                        results.extend(configs)

                return results if results else None
    return None


def _parse_ech_config_list(data: bytes) -> list[dict]:
    """解析 ECHConfigList，提取每个配置的 public_name 和原始 base64。"""
    results = []
    if len(data) < 2:
        return results
    total_len = struct.unpack("!H", data[0:2])[0]
    pos = 2
    end = 2 + total_len
    while pos + 4 <= end and pos + 4 <= len(data):
        # ECHConfig: version(2) + length(2) + contents
        version = struct.unpack("!H", data[pos:pos+2])[0]
        cfg_len = struct.unpack("!H", data[pos+2:pos+4])[0]
        cfg_raw = data[pos:pos+4+cfg_len]
        cfg_contents = data[pos+4:pos+4+cfg_len]
        pos += 4 + cfg_len

        if version != 0xFE0D:
            continue  # 只处理当前草案版本

        # contents: key_config(ECHKeyConfig) + maximum_name_length(1) + public_name(vec8) + extensions(vec16)
        # ECHKeyConfig: config_id(1) + kem_id(2) + public_key(vec16) + cipher_suites(vec16 of 4-byte)
        cp = 0
        if cp + 1 > len(cfg_contents): continue
        # config_id
        cp += 1
        if cp + 2 > len(cfg_contents): continue
        # kem_id
        cp += 2
        if cp + 2 > len(cfg_contents): continue
        pk_len = struct.unpack("!H", cfg_contents[cp:cp+2])[0]
        cp += 2 + pk_len
        if cp + 2 > len(cfg_contents): continue
        cs_len = struct.unpack("!H", cfg_contents[cp:cp+2])[0]
        cp += 2 + cs_len
        if cp + 1 > len(cfg_contents): continue
        # maximum_name_length
        cp += 1
        if cp + 1 > len(cfg_contents): continue
        pn_len = cfg_contents[cp]
        cp += 1
        if cp + pn_len > len(cfg_contents): continue
        public_name = cfg_contents[cp:cp+pn_len].decode(errors="replace")
        results.append({
            "version": f"0x{version:04X}",
            "public_name": public_name,
            "raw_b64": base64.b64encode(cfg_raw).decode(),
        })
    return results


# ── 用 openssl s_client 发起真实 ECH 握手（验证 + 计时）────────────────────

def _openssl_ech_connect(
    openssl_bin: str,
    domain: str,
    ech_config_b64: str,
    timeout: float,
    use_ech: bool = True,
) -> tuple[bool, float]:
    """
    调用 openssl s_client 发起握手，返回 (success, latency_ms)。
    use_ech=False 时做普通 TLS 握手用于对比延迟。
    """
    cmd = [
        openssl_bin, "s_client",
        "-connect", f"{domain}:443",
        "-servername", domain,
        "-noservercert",          # 不验证证书
        "-quiet",
        "-no_ign_eof",
    ]
    if use_ech:
        cmd += ["-ech_config_list", ech_config_b64]

    start = time.perf_counter()
    try:
        proc = subprocess.run(
            cmd,
            input=b"HEAD / HTTP/1.0\r\n\r\n",
            capture_output=True,
            timeout=timeout,
        )
        elapsed_ms = (time.perf_counter() - start) * 1000
        # 握手成功的标志：stderr 中出现 "Verify return code" 或 stdout 非空
        ok = (b"CONNECTED" in proc.stderr or
              b"Verify return code" in proc.stderr or
              proc.returncode == 0)
        return ok, elapsed_ms
    except (subprocess.TimeoutExpired, FileNotFoundError):
        elapsed_ms = (time.perf_counter() - start) * 1000
        return False, elapsed_ms


# ── 核心：单域名完整探测流程 ────────────────────────────────────────────────

async def probe_domain(
    domain: str,
    openssl_bin: str,
    timeout: float,
    loop: asyncio.AbstractEventLoop,
) -> ProbeResult:
    result = ProbeResult(domain=domain)

    # ① 建立原始 TCP 连接，发送含随机 ECH 的 ClientHello
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(domain, 443),
            timeout=timeout,
        )
    except Exception as e:
        result.error = f"TCP connect failed: {e}"
        return result

    try:
        ch = build_client_hello(domain, ech_data=b"trigger_hrr")
        writer.write(ch)
        await writer.drain()

        # 读取最多 8 KB 的响应（足以容纳 ServerHello/HRR）
        raw = b""
        try:
            while len(raw) < 8192:
                chunk = await asyncio.wait_for(reader.read(4096), timeout=timeout)
                if not chunk:
                    break
                raw += chunk
                # 若已收到 ServerHello 记录，可提前停止
                if len(raw) > 512:
                    break
        except asyncio.TimeoutError:
            pass
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass

    if not raw:
        result.error = "No response from server"
        return result

    # ② 解析响应，寻找 HelloRetryRequest 中的 ECH 配置
    ech_configs = parse_hrr_ech_configs(raw)

    if not ech_configs:
        # 没有 HRR / 没有 ECH 扩展 → 服务器不支持 ECH
        result.supports_ech = False
        return result

    result.hrr_received = True
    result.supports_ech = True
    first = ech_configs[0]
    result.ech_public_name = first["public_name"]
    result.ech_config_b64  = first["raw_b64"]

    # ③ 用真实配置验证 ECH 握手（委托给 openssl 命令行）
    if os.path.isfile(openssl_bin):
        ok_ech, lat_ech = await loop.run_in_executor(
            None,
            _openssl_ech_connect,
            openssl_bin, domain, first["raw_b64"], timeout, True,
        )
        result.validation_ok = ok_ech
        result.latency_ech_ms = round(lat_ech, 2)

        # ④ 普通 TLS 握手（对比延迟）
        _, lat_plain = await loop.run_in_executor(
            None,
            _openssl_ech_connect,
            openssl_bin, domain, first["raw_b64"], timeout, False,
        )
        result.latency_plain_ms = round(lat_plain, 2)
        if result.latency_ech_ms and result.latency_plain_ms:
            result.latency_delta_ms = round(
                result.latency_ech_ms - result.latency_plain_ms, 2
            )
    else:
        # openssl 不可用时，只记录 HRR 发现，不做验证
        result.validation_ok = None

    return result


# ── 主程序 ──────────────────────────────────────────────────────────────────

async def main(args):
    out_dir = Path(args.output)
    out_dir.mkdir(parents=True, exist_ok=True)

    domains = [
        d.strip() for d in Path(args.domains).read_text().splitlines()
        if d.strip() and not d.startswith("#")
    ]
    print(f"[*] 共 {len(domains)} 个域名待探测，并发={args.concurrency}，超时={args.timeout}s")

    semaphore = asyncio.Semaphore(args.concurrency)
    loop = asyncio.get_event_loop()

    async def bounded_probe(domain):
        async with semaphore:
            r = await probe_domain(domain, args.openssl, args.timeout, loop)
            status = "✓ ECH" if r.supports_ech else ("✗ no ECH" if not r.error else f"✗ {r.error}")
            pub = f" → {r.ech_public_name}" if r.ech_public_name else ""
            delta = f" Δ{r.latency_delta_ms:+.1f}ms" if r.latency_delta_ms is not None else ""
            print(f"  {domain:<40} {status}{pub}{delta}")
            return r

    results = await asyncio.gather(*[bounded_probe(d) for d in domains])

    # ── 写入 JSON ──
    json_path = out_dir / "results.json"
    with open(json_path, "w") as f:
        json.dump([asdict(r) for r in results], f, indent=2, ensure_ascii=False)

    # ── 写入 CSV ──
    csv_path = out_dir / "results.csv"
    fields = list(asdict(results[0]).keys()) if results else []
    with open(csv_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows([asdict(r) for r in results])

    # ── 汇总 ──
    ech_domains   = [r for r in results if r.supports_ech]
    valid_domains = [r for r in ech_domains if r.validation_ok]
    deltas = [r.latency_delta_ms for r in ech_domains if r.latency_delta_ms is not None]

    summary_lines = [
        "=" * 55,
        "ECH 探测结果摘要",
        "=" * 55,
        f"总探测域名:          {len(results)}",
        f"发现 ECH 支持:       {len(ech_domains)} ({len(ech_domains)/max(len(results),1)*100:.1f}%)",
        f"ECH 握手验证通过:    {len(valid_domains)}",
        "",
        "── 各 public_name 的域名数量 ──",
    ]

    from collections import Counter
    pub_counts = Counter(r.ech_public_name for r in ech_domains if r.ech_public_name)
    for pub_name, cnt in pub_counts.most_common():
        summary_lines.append(f"  {pub_name:<45} {cnt:>4}")

    if deltas:
        import statistics
        summary_lines += [
            "",
            "── ECH 延迟额外开销（ms）──",
            f"  中位数:  {statistics.median(deltas):+.2f} ms",
            f"  平均值:  {statistics.mean(deltas):+.2f} ms",
            f"  最小值:  {min(deltas):+.2f} ms",
            f"  最大值:  {max(deltas):+.2f} ms",
        ]

    summary_lines += ["=" * 55]
    summary_text = "\n".join(summary_lines)
    print(summary_text)
    (out_dir / "summary.txt").write_text(summary_text)

    print(f"\n[*] 结果已保存至 {out_dir}/")
    print(f"    {json_path.name}  — 完整 JSON")
    print(f"    {csv_path.name}   — CSV 格式")
    print(f"    summary.txt       — 文字摘要")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ECH 部署探测器 (HelloRetryRequest 方法)")
    parser.add_argument("--domains",     required=True,  help="域名列表文件，每行一个")
    parser.add_argument("--openssl",     default="openssl", help="OpenSSL ECH 二进制路径")
    parser.add_argument("--concurrency", type=int, default=20, help="并发协程数")
    parser.add_argument("--timeout",     type=float, default=5.0, help="每域名超时（秒）")
    parser.add_argument("--output",      default="results/", help="输出目录")
    args = parser.parse_args()

    asyncio.run(main(args))
