#!/usr/bin/env python3
"""
probe_ech.py — ECH 部署探测器（修复版）

主要修复：
  1. ClientHello 补全 supported_groups + signature_algorithms 扩展
     （缺这两个扩展，服务器会直接发 alert，而不是 HRR）
  2. socket 读取改为按 TLS 记录头读完整记录，不再截断
  3. HRR 解析中 ECHConfigList 偏移计算修正
  4. 伪 ECH 格式更贴近草案规范
"""

import argparse
import asyncio
import base64
import csv
import json
import os
import struct
import subprocess
import time
from collections import Counter
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Optional

# ── TLS 常量 ─────────────────────────────────────────────────────────────────

TLS_RECORD_HANDSHAKE       = 0x16
TLS_HS_CLIENT_HELLO        = 0x01
TLS_HS_SERVER_HELLO        = 0x02
TLS_EXT_SNI                = 0x0000
TLS_EXT_SUPPORTED_GROUPS   = 0x000A   # ← 之前版本缺少，必须有
TLS_EXT_SIG_ALGS           = 0x000D   # ← 之前版本缺少，必须有
TLS_EXT_KEY_SHARE          = 0x0033
TLS_EXT_SUPPORTED_VERSIONS = 0x002B
TLS_EXT_ECH                = 0xFE0D

TLS_VERSION_COMPAT         = 0x0303
TLS_VERSION_13             = 0x0304

# HelloRetryRequest 的固定 random（RFC 8446 §4.1.3）
HRR_MAGIC = bytes([
    0xCF,0x21,0xAD,0x74,0xE5,0x9A,0x61,0x11,
    0xBE,0x1D,0x8C,0x02,0x1E,0x65,0xB8,0x91,
    0xC2,0xA2,0x11,0x16,0x7A,0xBB,0x8C,0x5E,
    0x07,0x9E,0x09,0xE2,0xC8,0xA8,0x33,0x9C,
])


# ── 构造工具 ──────────────────────────────────────────────────────────────────

def ext(t: int, d: bytes) -> bytes:
    return struct.pack("!HH", t, len(d)) + d

def vec8(d: bytes) -> bytes:
    return struct.pack("!B", len(d)) + d

def vec16(d: bytes) -> bytes:
    return struct.pack("!H", len(d)) + d


def build_client_hello(sni: str) -> bytes:
    """
    构造完整 TLS 1.3 ClientHello，携带故意无效的 ECH 扩展。
    服务器无法解密 ECH → 按规范必须回复 HelloRetryRequest（含真实 ECH 配置）。

    必须包含的扩展（缺少任意一个，服务器会发 alert 而非 HRR）：
      SNI / supported_versions / supported_groups / signature_algorithms / key_share / ECH
    """

    # SNI
    sni_b = sni.encode()
    sni_ext = ext(TLS_EXT_SNI,
        vec16(struct.pack("!BH", 0, len(sni_b)) + sni_b))

    # supported_versions: 只声明 TLS 1.3
    sv_ext = ext(TLS_EXT_SUPPORTED_VERSIONS,
        vec8(struct.pack("!H", TLS_VERSION_13)))

    # supported_groups: x25519 / x448 / P-256 / P-384
    groups = struct.pack("!HHHH", 0x001D, 0x001E, 0x0017, 0x0018)
    sg_ext = ext(TLS_EXT_SUPPORTED_GROUPS, vec16(groups))

    # signature_algorithms
    sig_algs = struct.pack("!HHHHHH",
        0x0403,   # ecdsa_secp256r1_sha256
        0x0503,   # ecdsa_secp384r1_sha384
        0x0804,   # rsa_pss_rsae_sha256
        0x0805,   # rsa_pss_rsae_sha384
        0x0806,   # rsa_pss_rsae_sha512
        0x0401,   # rsa_pkcs1_sha256
    )
    sa_ext = ext(TLS_EXT_SIG_ALGS, vec16(sig_algs))

    # key_share: x25519
    ks_entry = struct.pack("!H", 0x001D) + vec16(os.urandom(32))
    ks_ext = ext(TLS_EXT_KEY_SHARE, vec16(ks_entry))

    # 伪 ECH（draft-ietf-tls-esni-24 §5 格式）
    # type=outer(0) + cipher_suite(4) + config_id=0xFF(不存在) + enc + payload
    # config_id=0xFF 几乎不可能存在于服务器，触发 HRR
    fake_ech = (
        b"\x00"
        + struct.pack("!HH", 0x0020, 0x0001)   # KEM=DHKEM(X25519), AEAD=AES-128-GCM
        + b"\xFF"                               # config_id (不存在)
        + vec16(os.urandom(32))                 # enc
        + vec16(os.urandom(128))                # payload
    )
    ech_ext = ext(TLS_EXT_ECH, fake_ech)

    extensions = sni_ext + sv_ext + sg_ext + sa_ext + ks_ext + ech_ext

    hello_body = (
        struct.pack("!H", TLS_VERSION_COMPAT)
        + os.urandom(32)
        + b"\x00"
        + vec16(b"\x13\x01\x13\x02\x13\x03")
        + b"\x01\x00"
        + vec16(extensions)
    )

    hs = (
        struct.pack("!B", TLS_HS_CLIENT_HELLO)
        + struct.pack("!I", len(hello_body))[1:]
        + hello_body
    )
    return struct.pack("!BHH", TLS_RECORD_HANDSHAKE, TLS_VERSION_COMPAT, len(hs)) + hs


# ── 按 TLS 记录头读完整响应 ───────────────────────────────────────────────────

async def read_tls_records(reader: asyncio.StreamReader, timeout: float) -> bytes:
    """
    之前版本读到 512 字节就 break，会截断跨多个 TCP 段的 HRR 响应。
    现在改为按记录头（5字节）逐条读取完整记录。
    """
    buf = b""
    deadline = time.monotonic() + timeout
    try:
        while time.monotonic() < deadline:
            remaining = max(deadline - time.monotonic(), 0.1)
            try:
                header = await asyncio.wait_for(reader.readexactly(5), timeout=remaining)
            except (asyncio.IncompleteReadError, asyncio.TimeoutError):
                break

            rec_type = header[0]
            rec_len  = struct.unpack("!H", header[3:5])[0]

            remaining = max(deadline - time.monotonic(), 0.1)
            try:
                body = await asyncio.wait_for(
                    reader.readexactly(rec_len), timeout=remaining)
            except (asyncio.IncompleteReadError, asyncio.TimeoutError):
                break

            buf += header + body

            # Alert → 停止
            if rec_type == 0x15:
                break
            # 握手记录：收到 ServerHello 后再多读一条，其他类型停止
            if rec_type == TLS_RECORD_HANDSHAKE and body:
                if body[0] == TLS_HS_SERVER_HELLO:
                    continue
                if body[0] in (0x08, 0x0B, 0x0F, 0x14):
                    break
    except Exception:
        pass
    return buf


# ── 解析 HRR，提取 ECHConfigList ──────────────────────────────────────────────

def parse_hrr_ech_configs(data: bytes) -> Optional[list[dict]]:
    pos = 0
    while pos + 5 <= len(data):
        rec_type = data[pos]
        rec_len  = struct.unpack("!H", data[pos+3:pos+5])[0]
        pos += 5
        if pos + rec_len > len(data):
            break
        payload = data[pos:pos+rec_len]
        pos += rec_len

        if rec_type != TLS_RECORD_HANDSHAKE:
            continue

        hp = 0
        while hp + 4 <= len(payload):
            hs_type = payload[hp]
            hs_len  = struct.unpack("!I", b"\x00" + payload[hp+1:hp+4])[0]
            hp += 4
            if hp + hs_len > len(payload):
                break
            body = payload[hp:hp+hs_len]
            hp  += hs_len

            if hs_type != TLS_HS_SERVER_HELLO or len(body) < 34:
                continue
            if body[2:34] != HRR_MAGIC:
                continue

            # 解析扩展
            p = 34
            if p >= len(body): continue
            sid_len = body[p]; p += 1 + sid_len   # session_id
            p += 3                                  # cipher_suite(2) + compression(1)
            if p + 2 > len(body): continue
            exts_len = struct.unpack("!H", body[p:p+2])[0]; p += 2
            exts_end = p + exts_len
            configs = []

            while p + 4 <= exts_end:
                e_type = struct.unpack("!H", body[p:p+2])[0]
                e_len  = struct.unpack("!H", body[p+2:p+4])[0]
                p += 4
                e_data = body[p:p+e_len]; p += e_len
                if e_type == TLS_EXT_ECH:
                    configs.extend(_parse_ech_config_list(e_data))

            return configs if configs else None
    return None


def _parse_ech_config_list(data: bytes) -> list[dict]:
    results = []
    if len(data) < 2:
        return results
    total = struct.unpack("!H", data[0:2])[0]
    p, end = 2, min(2 + total, len(data))

    while p + 4 <= end:
        version = struct.unpack("!H", data[p:p+2])[0]
        cfg_len = struct.unpack("!H", data[p+2:p+4])[0]
        raw     = data[p:p+4+cfg_len]
        body    = data[p+4:p+4+cfg_len]
        p      += 4 + cfg_len

        if version != 0xFE0D:
            continue

        cp = 0
        try:
            cp += 1                                                     # config_id
            cp += 2                                                     # kem_id
            pk_len = struct.unpack("!H", body[cp:cp+2])[0]; cp += 2+pk_len  # public_key
            cs_len = struct.unpack("!H", body[cp:cp+2])[0]; cp += 2+cs_len  # cipher_suites
            cp += 1                                                     # max_name_len
            pn_len = body[cp]; cp += 1
            public_name = body[cp:cp+pn_len].decode(errors="replace")
        except (struct.error, IndexError):
            continue

        results.append({
            "version":     f"0x{version:04X}",
            "public_name": public_name,
            "raw_b64":     base64.b64encode(raw).decode(),
        })
    return results


# ── openssl s_client 验证握手 + 测量延迟 ─────────────────────────────────────

def openssl_connect(
    openssl_bin: str, domain: str,
    ech_b64: Optional[str], timeout: float,
) -> tuple[bool, float]:
    cmd = [openssl_bin, "s_client",
           "-connect", f"{domain}:443",
           "-servername", domain,
           "-noservercert", "-quiet", "-no_ign_eof"]
    if ech_b64:
        cmd += ["-ech_config_list", ech_b64]
    t0 = time.perf_counter()
    try:
        r = subprocess.run(cmd, input=b"HEAD / HTTP/1.0\r\n\r\n",
                           capture_output=True, timeout=timeout)
        ms = (time.perf_counter() - t0) * 1000
        ok = b"CONNECTED" in r.stderr or b"Verify return code" in r.stderr
        return ok, round(ms, 2)
    except Exception:
        return False, round((time.perf_counter() - t0) * 1000, 2)


# ── 单域名探测 ────────────────────────────────────────────────────────────────

@dataclass
class ProbeResult:
    domain: str
    supports_ech: bool = False
    ech_public_name: Optional[str] = None
    ech_config_b64:  Optional[str] = None
    hrr_received:    bool = False
    validation_ok:   Optional[bool] = None
    latency_ech_ms:  Optional[float] = None
    latency_plain_ms: Optional[float] = None
    latency_delta_ms: Optional[float] = None
    error: Optional[str] = None


async def probe_domain(
    domain: str, openssl_bin: str,
    timeout: float, loop: asyncio.AbstractEventLoop,
) -> ProbeResult:
    res = ProbeResult(domain=domain)

    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(domain, 443), timeout=timeout)
    except Exception as e:
        res.error = f"connect: {e}"; return res

    try:
        writer.write(build_client_hello(domain))
        await writer.drain()
        raw = await read_tls_records(reader, timeout)
    except Exception as e:
        res.error = f"io: {e}"; return res
    finally:
        writer.close()
        try: await writer.wait_closed()
        except Exception: pass

    if not raw:
        res.error = "no response"; return res

    configs = parse_hrr_ech_configs(raw)
    if not configs:
        return res

    res.hrr_received    = True
    res.supports_ech    = True
    res.ech_public_name = configs[0]["public_name"]
    res.ech_config_b64  = configs[0]["raw_b64"]

    if os.path.isfile(openssl_bin):
        ok, lat_ech = await loop.run_in_executor(
            None, openssl_connect, openssl_bin, domain, res.ech_config_b64, timeout)
        _, lat_plain = await loop.run_in_executor(
            None, openssl_connect, openssl_bin, domain, None, timeout)
        res.validation_ok    = ok
        res.latency_ech_ms   = lat_ech
        res.latency_plain_ms = lat_plain
        res.latency_delta_ms = round(lat_ech - lat_plain, 2)

    return res


# ── 主程序 ────────────────────────────────────────────────────────────────────

async def main(args):
    out = Path(args.output)
    out.mkdir(parents=True, exist_ok=True)

    domains = [l.strip() for l in Path(args.domains).read_text().splitlines()
               if l.strip() and not l.startswith("#")]
    print(f"[*] {len(domains)} 个域名，并发={args.concurrency}，超时={args.timeout}s\n")

    sem  = asyncio.Semaphore(args.concurrency)
    loop = asyncio.get_event_loop()

    async def run(d):
        async with sem:
            r = await probe_domain(d, args.openssl, args.timeout, loop)
            tag   = "✓ ECH" if r.supports_ech else ("✗ err" if r.error else "✗ none")
            pub   = f" → {r.ech_public_name}" if r.ech_public_name else ""
            delta = f" Δ{r.latency_delta_ms:+.1f}ms" if r.latency_delta_ms is not None else ""
            print(f"  {d:<40} {tag}{pub}{delta}")
            return r

    results = await asyncio.gather(*[run(d) for d in domains])

    (out/"results.json").write_text(
        json.dumps([asdict(r) for r in results], indent=2, ensure_ascii=False))

    with open(out/"results.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(asdict(results[0]).keys()))
        w.writeheader(); w.writerows([asdict(r) for r in results])

    ech_r   = [r for r in results if r.supports_ech]
    valid_r = [r for r in ech_r if r.validation_ok]
    deltas  = [r.latency_delta_ms for r in ech_r if r.latency_delta_ms is not None]

    lines = ["="*52, "ECH 探测摘要", "="*52,
             f"总域名:       {len(results)}",
             f"支持 ECH:     {len(ech_r)} ({len(ech_r)/max(len(results),1)*100:.1f}%)",
             f"握手验证通过: {len(valid_r)}", "",
             "── public_name 分布 ──"]
    for name, cnt in Counter(
            r.ech_public_name for r in ech_r if r.ech_public_name).most_common():
        lines.append(f"  {name:<42} {cnt:>4}")

    if deltas:
        import statistics
        lines += ["", "── ECH 额外延迟 (ms) ──",
                  f"  中位数 {statistics.median(deltas):+.2f}  "
                  f"均值 {statistics.mean(deltas):+.2f}  "
                  f"min {min(deltas):+.2f}  max {max(deltas):+.2f}"]
    lines.append("="*52)

    summary = "\n".join(lines)
    print("\n" + summary)
    (out/"summary.txt").write_text(summary)
    print(f"\n结果 → {out}/")


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--domains",     required=True)
    p.add_argument("--openssl",     default="openssl")
    p.add_argument("--concurrency", type=int,   default=20)
    p.add_argument("--timeout",     type=float, default=5.0)
    p.add_argument("--output",      default="results/")
    asyncio.run(main(p.parse_args()))
