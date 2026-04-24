// probe_ech.go — ECH 部署探测器（Go 实现）
//
// 探测原理：向目标服务器发送携带故意无效 ECH 扩展的 TLS 1.3 ClientHello。
// 支持 ECH 的服务器无法解密该扩展，按规范（draft-ietf-tls-esni-24 §6.1.6）
// 必须回复 HelloRetryRequest 并在其 ECH 扩展中携带真实的 retry_configs。
// 本程序解析该响应，提取 ECHConfigList，并可选地用 ECH 分支的 openssl
// 做完整握手验证及延迟测量。

package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ── TLS 常量 ──────────────────────────────────────────────────────────────────

const (
	tlsRecordHandshake      = 0x16
	tlsRecordCCS            = 0x14 // ChangeCipherSpec
	tlsHSServerHello        = 0x02
	tlsHSClientHello        = 0x01
	tlsExtSNI               = 0x0000
	tlsExtSupportedGroups   = 0x000A
	tlsExtSigAlgs           = 0x000D
	tlsExtKeyShare          = 0x0033
	tlsExtSupportedVersions = 0x002B
	tlsExtECH               = 0xFE0D
	tlsVersionCompat        = 0x0303 // TLS 1.2 compat field
	tlsVersion13            = 0x0304
)

// HelloRetryRequest 的固定 random（RFC 8446 §4.1.3）
var hrrMagic = [32]byte{
	0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11,
	0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
	0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E,
	0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
}

// ── 字节构造工具 ──────────────────────────────────────────────────────────────

func u16(v uint16) []byte {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, v)
	return b
}

func tlsExt(extType uint16, data []byte) []byte {
	b := make([]byte, 4+len(data))
	binary.BigEndian.PutUint16(b[0:], extType)
	binary.BigEndian.PutUint16(b[2:], uint16(len(data)))
	copy(b[4:], data)
	return b
}

func prefixLen8(data []byte) []byte {
	b := make([]byte, 1+len(data))
	b[0] = byte(len(data))
	copy(b[1:], data)
	return b
}

func prefixLen16(data []byte) []byte {
	b := make([]byte, 2+len(data))
	binary.BigEndian.PutUint16(b[0:], uint16(len(data)))
	copy(b[2:], data)
	return b
}

func randomBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}

func concat(parts ...[]byte) []byte {
	n := 0
	for _, p := range parts {
		n += len(p)
	}
	out := make([]byte, 0, n)
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// ── ClientHello 构造 ───────────────────────────────────────────────────────────

func buildClientHello(sni string) []byte {
	sniData := concat(
		[]byte{0x00},
		u16(uint16(len(sni))),
		[]byte(sni),
	)
	sniExt := tlsExt(tlsExtSNI, prefixLen16(sniData))
	svExt := tlsExt(tlsExtSupportedVersions, prefixLen8(u16(tlsVersion13)))

	var groups []byte
	for _, g := range []uint16{0x001D, 0x001E, 0x0017, 0x0018} {
		groups = append(groups, u16(g)...)
	}
	sgExt := tlsExt(tlsExtSupportedGroups, prefixLen16(groups))

	var sigAlgs []byte
	for _, a := range []uint16{0x0403, 0x0503, 0x0804, 0x0805, 0x0806, 0x0401} {
		sigAlgs = append(sigAlgs, u16(a)...)
	}
	saExt := tlsExt(tlsExtSigAlgs, prefixLen16(sigAlgs))

	ksEntry := concat(u16(0x001D), prefixLen16(randomBytes(32)))
	ksExt := tlsExt(tlsExtKeyShare, prefixLen16(ksEntry))

	fakeECH := concat(
		[]byte{0x00},
		u16(0x0001),
		u16(0x0001),
		[]byte{0xFF},
		prefixLen16(randomBytes(32)),
		prefixLen16(randomBytes(128)),
	)
	echExt := tlsExt(tlsExtECH, fakeECH)

	extensions := concat(sniExt, svExt, sgExt, saExt, ksExt, echExt)

	cipherSuites := []byte{0x13, 0x01, 0x13, 0x02, 0x13, 0x03}
	helloBody := concat(
		u16(tlsVersionCompat),
		randomBytes(32),
		[]byte{0x00},
		prefixLen16(cipherSuites),
		[]byte{0x01, 0x00},
		prefixLen16(extensions),
	)

	hsLen := len(helloBody)
	hs := concat(
		[]byte{tlsHSClientHello, byte(hsLen >> 16), byte(hsLen >> 8), byte(hsLen)},
		helloBody,
	)

	return concat(
		[]byte{tlsRecordHandshake},
		u16(tlsVersionCompat),
		u16(uint16(len(hs))),
		hs,
	)
}

// ── TLS 记录读取 ───────────────────────────────────────────────────────────────

func readTLSRecords(conn net.Conn) []byte {
	var buf []byte
	for {
		var hdr [5]byte
		if _, err := io.ReadFull(conn, hdr[:]); err != nil {
			break
		}
		recType := hdr[0]
		recLen := int(binary.BigEndian.Uint16(hdr[3:5]))

		body := make([]byte, recLen)
		if _, err := io.ReadFull(conn, body); err != nil {
			break
		}
		buf = append(buf, hdr[:]...)
		buf = append(buf, body...)

		switch recType {
		case 0x15:
			return buf
		case tlsRecordCCS:
			return buf
		case tlsRecordHandshake:
			if len(body) == 0 {
				return buf
			}
			switch body[0] {
			case tlsHSServerHello:
				continue
			case 0x08, 0x0B, 0x0F, 0x14:
				return buf
			default:
				return buf
			}
		default:
			return buf
		}
	}
	return buf
}

// ── ECHConfigList 解析 ────────────────────────────────────────────────────────

type echConfig struct {
	Version    string `json:"version"`
	PublicName string `json:"public_name"`
	RawB64     string `json:"raw_b64"`
}

func parseHRRECHConfigs(data []byte) []echConfig {
	pos := 0
	for pos+5 <= len(data) {
		recType := data[pos]
		recLen := int(binary.BigEndian.Uint16(data[pos+3 : pos+5]))
		pos += 5
		if pos+recLen > len(data) {
			break
		}
		payload := data[pos : pos+recLen]
		pos += recLen

		if recType != tlsRecordHandshake {
			continue
		}

		hp := 0
		for hp+4 <= len(payload) {
			hsType := payload[hp]
			hsLen := int(uint32(payload[hp+1])<<16 |
				uint32(payload[hp+2])<<8 |
				uint32(payload[hp+3]))
			hp += 4
			if hp+hsLen > len(payload) {
				break
			}
			body := payload[hp : hp+hsLen]
			hp += hsLen

			if hsType != tlsHSServerHello || len(body) < 36 {
				continue
			}
			if [32]byte(body[2:34]) != hrrMagic {
				continue
			}

			p := 34
			if p >= len(body) {
				continue
			}
			sidLen := int(body[p])
			p += 1 + sidLen
			p += 3
			if p+2 > len(body) {
				continue
			}
			extsLen := int(binary.BigEndian.Uint16(body[p : p+2]))
			p += 2
			extsEnd := p + extsLen

			var configs []echConfig
			for p+4 <= extsEnd && p+4 <= len(body) {
				eType := binary.BigEndian.Uint16(body[p : p+2])
				eLen := int(binary.BigEndian.Uint16(body[p+2 : p+4]))
				p += 4
				if p+eLen > len(body) {
					break
				}
				eData := body[p : p+eLen]
				p += eLen
				if eType == tlsExtECH {
					configs = append(configs, parseECHConfigList(eData)...)
				}
			}
			if len(configs) > 0 {
				return configs
			}
		}
	}
	return nil
}

func parseECHConfigList(data []byte) []echConfig {
	if len(data) < 2 {
		return nil
	}
	total := int(binary.BigEndian.Uint16(data[0:2]))
	p := 2
	end := 2 + total
	if end > len(data) {
		end = len(data)
	}

	var results []echConfig
	for p+4 <= end {
		version := binary.BigEndian.Uint16(data[p : p+2])
		cfgLen := int(binary.BigEndian.Uint16(data[p+2 : p+4]))
		if p+4+cfgLen > len(data) {
			break
		}
		raw := data[p : p+4+cfgLen]
		body := data[p+4 : p+4+cfgLen]
		p += 4 + cfgLen

		if version != 0xFE0D {
			continue
		}
		name, ok := parseECHPublicName(body)
		if !ok {
			continue
		}
		results = append(results, echConfig{
			Version:    fmt.Sprintf("0x%04X", version),
			PublicName: name,
			RawB64:     base64.StdEncoding.EncodeToString(raw),
		})
	}
	return results
}

func parseECHPublicName(body []byte) (string, bool) {
	p := 0
	need := func(n int) bool {
		if p+n > len(body) {
			return false
		}
		p += n
		return true
	}
	readU16 := func() (int, bool) {
		if p+2 > len(body) {
			return 0, false
		}
		v := int(binary.BigEndian.Uint16(body[p : p+2]))
		p += 2
		return v, true
	}

	if !need(1) { return "", false }
	if !need(2) { return "", false }
	pkLen, ok := readU16()
	if !ok || !need(pkLen) { return "", false }
	csLen, ok := readU16()
	if !ok || !need(csLen) { return "", false }
	if !need(1) { return "", false }
	if p >= len(body) { return "", false }
	pnLen := int(body[p])
	if !need(1+pnLen) { return "", false }
	return string(body[p-pnLen : p]), true
}

// ── OpenSSL 验证 ──────────────────────────────────────────────────────────────

func opensslConnect(opensslBin, domain string, echB64 *string, timeout time.Duration) (bool, float64) {
	args := []string{
		"s_client",
		"-connect", domain + ":443",
		"-servername", domain,
		"-noservercert", "-quiet", "-no_ign_eof",
	}
	if echB64 != nil {
		args = append(args, "-ech_config_list", *echB64)
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	t0 := time.Now()
	cmd := exec.CommandContext(ctx, opensslBin, args...)
	cmd.Stdin = strings.NewReader("HEAD / HTTP/1.0\r\n\r\n")
	out, _ := cmd.CombinedOutput()
	ms := roundMs(time.Since(t0))

	ok := bytes.Contains(out, []byte("CONNECTED")) ||
		bytes.Contains(out, []byte("Verify return code"))
	return ok, ms
}

func roundMs(d time.Duration) float64 {
	return math.Round(d.Seconds()*100000) / 100
}

// ── 单域名探测 ────────────────────────────────────────────────────────────────

type probeResult struct {
	Domain         string   `json:"domain"`
	SupportsECH    bool     `json:"supports_ech"`
	ECHPublicName  *string  `json:"ech_public_name"`
	ECHConfigB64   *string  `json:"ech_config_b64"`
	HRRReceived    bool     `json:"hrr_received"`
	ValidationOK   *bool    `json:"validation_ok"`
	LatencyECHMs   *float64 `json:"latency_ech_ms"`
	LatencyPlainMs *float64 `json:"latency_plain_ms"`
	LatencyDeltaMs *float64 `json:"latency_delta_ms"`
	Error          *string  `json:"error"`
}

func ptrStr(s string) *string   { return &s }
func ptrBool(b bool) *bool      { return &b }
func ptrF64(f float64) *float64 { return &f }

func probeDomain(domain, opensslBin string, timeout time.Duration) probeResult {
	res := probeResult{Domain: domain}
	deadline := time.Now().Add(timeout)

	conn, err := net.DialTimeout("tcp", domain+":443", timeout)
	if err != nil {
		res.Error = ptrStr(fmt.Sprintf("connect: %v", err))
		return res
	}
	defer conn.Close()
	conn.SetDeadline(deadline) //nolint:errcheck

	if _, err := conn.Write(buildClientHello(domain)); err != nil {
		res.Error = ptrStr(fmt.Sprintf("write: %v", err))
		return res
	}

	raw := readTLSRecords(conn)
	if len(raw) == 0 {
		res.Error = ptrStr("no response")
		return res
	}

	configs := parseHRRECHConfigs(raw)
	if len(configs) == 0 {
		return res
	}

	res.HRRReceived = true
	res.SupportsECH = true
	res.ECHPublicName = ptrStr(configs[0].PublicName)
	res.ECHConfigB64 = ptrStr(configs[0].RawB64)

	if _, err := os.Stat(opensslBin); err == nil {
		ok, latECH := opensslConnect(opensslBin, domain, res.ECHConfigB64, timeout)
		_, latPlain := opensslConnect(opensslBin, domain, nil, timeout)
		delta := math.Round((latECH-latPlain)*100) / 100
		res.ValidationOK = ptrBool(ok)
		res.LatencyECHMs = ptrF64(latECH)
		res.LatencyPlainMs = ptrF64(latPlain)
		res.LatencyDeltaMs = ptrF64(delta)
	}
	return res
}

// ── 统计工具 ──────────────────────────────────────────────────────────────────

func median(vals []float64) float64 {
	if len(vals) == 0 {
		return 0
	}
	cp := make([]float64, len(vals))
	copy(cp, vals)
	sort.Float64s(cp)
	n := len(cp)
	if n%2 == 0 {
		return (cp[n/2-1] + cp[n/2]) / 2
	}
	return cp[n/2]
}

func mean(vals []float64) float64 {
	if len(vals) == 0 {
		return 0
	}
	sum := 0.0
	for _, v := range vals {
		sum += v
	}
	return sum / float64(len(vals))
}

// ── 输出格式化 ────────────────────────────────────────────────────────────────

func derefStr(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

func derefBoolStr(p *bool) string {
	if p == nil {
		return ""
	}
	return strconv.FormatBool(*p)
}

func derefF64Str(p *float64) string {
	if p == nil {
		return ""
	}
	return strconv.FormatFloat(*p, 'f', 2, 64)
}

// ── 主程序 ────────────────────────────────────────────────────────────────────

func main() {
	domainsFile := flag.String("domains", "", "域名列表文件路径（必填）")
	opensslBin  := flag.String("openssl", "openssl", "ECH 分支 openssl 路径（可选）")
	concurrency := flag.Int("concurrency", 20, "最大并发探测数")
	timeoutSec  := flag.Float64("timeout", 5.0, "每域名超时（秒）")
	outputDir   := flag.String("output", "results/", "结果输出目录")
	flag.Parse()

	if *domainsFile == "" {
		fmt.Fprintln(os.Stderr, "error: --domains 为必填参数")
		os.Exit(1)
	}

	timeout := time.Duration(float64(time.Second) * *timeoutSec)

	f, err := os.Open(*domainsFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: 无法打开 %s: %v\n", *domainsFile, err)
		os.Exit(1)
	}
	var domains []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		domains = append(domains, line)
	}
	f.Close()

	if len(domains) == 0 {
		fmt.Fprintln(os.Stderr, "error: 域名列表为空")
		os.Exit(1)
	}
	fmt.Printf("[*] %d 个域名，并发=%d，超时=%.1fs\n\n",
		len(domains), *concurrency, *timeoutSec)

	if err := os.MkdirAll(*outputDir, 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "error: 无法创建输出目录: %v\n", err)
		os.Exit(1)
	}

	results := make([]probeResult, len(domains))
	sem := make(chan struct{}, *concurrency)
	var wg sync.WaitGroup

	for i, d := range domains {
		wg.Add(1)
		go func(idx int, domain string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			r := probeDomain(domain, *opensslBin, timeout)
			results[idx] = r

			tag := "✗ none"
			if r.SupportsECH {
				tag = "✓ ECH "
			} else if r.Error != nil {
				tag = "✗ err "
			}
			pub := ""
			if r.ECHPublicName != nil {
				pub = " → " + *r.ECHPublicName
			}
			delta := ""
			if r.LatencyDeltaMs != nil {
				delta = fmt.Sprintf(" Δ%+.1fms", *r.LatencyDeltaMs)
			}
			fmt.Printf("  %-40s %s%s%s\n", domain, tag, pub, delta)
		}(i, d)
	}
	wg.Wait()

	// results.json
	jsonOut, err := json.MarshalIndent(results, "", "  ")
	if err == nil {
		os.WriteFile(filepath.Join(*outputDir, "results.json"), jsonOut, 0o644) //nolint:errcheck
	}

	// results.csv
	if cf, err := os.Create(filepath.Join(*outputDir, "results.csv")); err == nil {
		w := csv.NewWriter(cf)
		_ = w.Write([]string{
			"domain", "supports_ech", "ech_public_name", "ech_config_b64",
			"hrr_received", "validation_ok",
			"latency_ech_ms", "latency_plain_ms", "latency_delta_ms", "error",
		})
		for _, r := range results {
			_ = w.Write([]string{
				r.Domain,
				strconv.FormatBool(r.SupportsECH),
				derefStr(r.ECHPublicName),
				derefStr(r.ECHConfigB64),
				strconv.FormatBool(r.HRRReceived),
				derefBoolStr(r.ValidationOK),
				derefF64Str(r.LatencyECHMs),
				derefF64Str(r.LatencyPlainMs),
				derefF64Str(r.LatencyDeltaMs),
				derefStr(r.Error),
			})
		}
		w.Flush()
		cf.Close()
	}

	// 统计摘要
	var echResults []probeResult
	var validCount int
	var deltas []float64
	nameCounts := map[string]int{}

	for _, r := range results {
		if !r.SupportsECH {
			continue
		}
		echResults = append(echResults, r)
		if r.ValidationOK != nil && *r.ValidationOK {
			validCount++
		}
		if r.LatencyDeltaMs != nil {
			deltas = append(deltas, *r.LatencyDeltaMs)
		}
		if r.ECHPublicName != nil {
			nameCounts[*r.ECHPublicName]++
		}
	}

	pct := 0.0
	if len(results) > 0 {
		pct = float64(len(echResults)) / float64(len(results)) * 100
	}

	var sb strings.Builder
	sep := strings.Repeat("=", 52)
	fmt.Fprintln(&sb, sep)
	fmt.Fprintln(&sb, "ECH 探测摘要")
	fmt.Fprintln(&sb, sep)
	fmt.Fprintf(&sb, "总域名:       %d\n", len(results))
	fmt.Fprintf(&sb, "支持 ECH:     %d (%.1f%%)\n", len(echResults), pct)
	fmt.Fprintf(&sb, "握手验证通过: %d\n", validCount)
	fmt.Fprintln(&sb)
	fmt.Fprintln(&sb, "── public_name 分布 ──")

	type kv = kvPair
	sorted := make([]kv, 0, len(nameCounts))
	for k, v := range nameCounts {
		sorted = append(sorted, kv{k, v})
	}
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].v != sorted[j].v {
			return sorted[i].v > sorted[j].v
		}
		return sorted[i].k < sorted[j].k
	})
	for _, entry := range sorted {
		fmt.Fprintf(&sb, "  %-42s %4d\n", entry.k, entry.v)
	}

	if len(deltas) > 0 {
		mn, mx := deltas[0], deltas[0]
		for _, d := range deltas[1:] {
			if d < mn { mn = d }
			if d > mx { mx = d }
		}
		fmt.Fprintln(&sb)
		fmt.Fprintln(&sb, "── ECH 额外延迟 (ms) ──")
		fmt.Fprintf(&sb, "  中位数 %+.2f  均值 %+.2f  min %+.2f  max %+.2f\n",
			median(deltas), mean(deltas), mn, mx)
	}
	fmt.Fprintln(&sb, sep)

	// GitHub Actions Step Summary 格式
	if summaryFile := os.Getenv("GITHUB_STEP_SUMMARY"); summaryFile != "" {
		writeMDSummary(summaryFile, results, echResults, pct, validCount, deltas, sorted, nameCounts)
	}

	summary := sb.String()
	fmt.Println("\n" + summary)
	os.WriteFile(filepath.Join(*outputDir, "summary.txt"), []byte(summary), 0o644) //nolint:errcheck
	fmt.Printf("结果 → %s\n", *outputDir)
}

type kvPair struct {
	k string
	v int
}

// writeMDSummary 将结果写入 GitHub Actions Step Summary（Markdown 格式）
func writeMDSummary(path string, results, echResults []probeResult, pct float64, validCount int,
	deltas []float64, sortedPairs []kvPair, nameCounts map[string]int) {

	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	defer f.Close()

	errCount := 0
	for _, r := range results {
		if r.Error != nil {
			errCount++
		}
	}

	fmt.Fprintf(f, "# 🔒 ECH 扫描结果\n\n")
	fmt.Fprintf(f, "| 指标 | 值 |\n|---|---|\n")
	fmt.Fprintf(f, "| 总域名 | %d |\n", len(results))
	fmt.Fprintf(f, "| ✅ 支持 ECH | **%d** (%.1f%%) |\n", len(echResults), pct)
	fmt.Fprintf(f, "| 握手验证通过 | %d |\n", validCount)
	fmt.Fprintf(f, "| ❌ 连接失败 | %d |\n", errCount)

	if len(deltas) > 0 {
		mn, mx := deltas[0], deltas[0]
		for _, d := range deltas[1:] {
			if d < mn { mn = d }
			if d > mx { mx = d }
		}
		fmt.Fprintf(f, "| ECH 延迟中位数 | %+.2f ms |\n", median(deltas))
		fmt.Fprintf(f, "| ECH 延迟范围 | %+.2f ~ %+.2f ms |\n", mn, mx)
	}

	fmt.Fprintf(f, "\n## 📊 public_name 分布\n\n")
	fmt.Fprintf(f, "| public_name | 域名数 |\n|---|---|\n")
	for _, entry := range sortedPairs {
		fmt.Fprintf(f, "| `%s` | %d |\n", entry.k, entry.v)
	}

	fmt.Fprintf(f, "\n## 📋 ECH 域名列表\n\n")
	fmt.Fprintf(f, "| 域名 | public_name | 验证 |\n|---|---|---|\n")
	for _, r := range echResults {
		pub := derefStr(r.ECHPublicName)
		val := ""
		if r.ValidationOK != nil {
			if *r.ValidationOK {
				val = "✅"
			} else {
				val = "❌"
			}
		}
		fmt.Fprintf(f, "| `%s` | `%s` | %s |\n", r.Domain, pub, val)
	}
}
