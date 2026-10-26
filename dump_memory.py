#!/usr/bin/env python3
"""dump_memory — 非注入内存 dump + 明文/key 搜索（逆向引擎「动态降级」工具节点）

复用 dexripper 的非注入思路：只读 /proc/<pid>/maps + /proc/<pid>/mem，
不 ptrace、不 hook、不注入 —— 绕加固壳（zxprotect / libjiagu 等）的反 frida / 反调试。

在逆向关联追踪引擎中的位置（reverse_engine_design.md §8.5）：
  静态追踪 → 死路（STATIC_DEAD_END）→ 动态降级（DUMP）→ 本工具 → MEM 节点
  → 工蚁对 findings 做四选一判断 → CONTAINS 边 → CONST/明文

部署：root 的 Android 设备（或 redroid 容器）上运行；需 Python 环境或通过 adb shell 执行。
  python dump_memory.py <package_name> <output_dir>
  python dump_memory.py --pid <pid> <output_dir>

输出：
  <output_dir>/dump_<pid>.bin      — 关键段内存镜像
  <output_dir>/findings.json       — 结构化发现（明文/key 候选 + 证据），供工蚁四选一
"""
from __future__ import annotations

import json
import os
import re
import sys
from dataclasses import dataclass, field
from typing import List, Optional, Tuple


# ── 内存段 ────────────────────────────────────────────────────────────────

@dataclass
class Region:
    """/proc/pid/maps 里的一段。"""
    start: int
    end: int
    perms: str
    path: str = ""

    @property
    def size(self) -> int:
        return self.end - self.start

    @property
    def readable(self) -> bool:
        return "r" in self.perms


# ── 进程定位 ──────────────────────────────────────────────────────────────

def find_pid(package: str) -> Optional[int]:
    """按包名找 pid（遍历 /proc/*/cmdline，避免依赖 pidof 的版本差异）。"""
    for pid in [p for p in os.listdir("/proc") if p.isdigit()]:
        try:
            with open(f"/proc/{pid}/cmdline", "rb") as f:
                cmdline = f.read().replace(b"\0", b" ").decode("utf-8", "ignore")
        except (OSError, PermissionError):
            continue
        if package in cmdline:
            return int(pid)
    return None


# ── maps 解析 ─────────────────────────────────────────────────────────────

# 关键段（优先 dump）：堆 + dalvik dex + scudo 堆 —— 解密数据/明文常驻这些段
_KEY_REGIONS = ("[heap]", "[anon:dalvik-", "[anon:scudo", "[anon:.bss]")


def parse_maps(pid: int) -> List[Region]:
    """解析 /proc/pid/maps，返回可读段。"""
    regions: List[Region] = []
    try:
        with open(f"/proc/{pid}/maps", "r") as f:
            for line in f:
                parts = line.split(None, 5)
                if len(parts) < 5:
                    continue
                addr, perms = parts[0], parts[1]
                path = parts[5].strip() if len(parts) == 6 else ""
                start_s, end_s = addr.split("-")
                r = Region(int(start_s, 16), int(end_s, 16), perms, path)
                if r.readable and r.size > 0:
                    regions.append(r)
    except (OSError, PermissionError) as e:
        print(f"[!] 无法读 maps: {e}", file=sys.stderr)
    return regions


def select_regions(regions: List[Region], max_total: int = 512 * 1024 * 1024) -> List[Region]:
    """优先选关键段（heap/dex/scudo），总大小不超 max_total，避免 dump 全内存。"""
    key = [r for r in regions if any(k in r.path for k in _KEY_REGIONS)]
    rest = [r for r in regions if r not in key]
    chosen: List[Region] = []
    total = 0
    for r in key + rest:
        if total + r.size > max_total:
            continue
        chosen.append(r)
        total += r.size
    return chosen


# ── 非注入读 mem ──────────────────────────────────────────────────────────

def dump_regions(pid: int, regions: List[Region], out_path: str) -> List[Tuple[Region, int]]:
    """非注入读 /proc/pid/mem，把选中段写入镜像；返回 [(region, 文件偏移)]。"""
    offsets: List[Tuple[Region, int]] = []
    try:
        with open(f"/proc/{pid}/mem", "rb", buffering=0) as mem, \
             open(out_path, "wb") as out:
            for r in regions:
                try:
                    mem.seek(r.start)
                    data = mem.read(r.size)
                except (OSError, ValueError):
                    continue  # 该段不可读（被保护），跳过
                if not data:
                    continue
                off = out.tell()
                out.write(data)
                offsets.append((r, off))
    except (OSError, PermissionError) as e:
        print(f"[!] 无法读 mem: {e}", file=sys.stderr)
    return offsets


# ── 明文搜索 ──────────────────────────────────────────────────────────────

_PLAINTEXT_PATTERNS = {
    "cn_text": re.compile(rb"[\xe4-\xe9][\x80-\xbf]{2}(?:[\xe4-\xe9][\x80-\xbf]{2}|[\x20-\x7e]){4,}"),
    "json": re.compile(rb"\{[^{}\n]{8,}\}"),
    "url": re.compile(rb"https?://[\x21-\x7e]{6,80}"),
    "timestamp": re.compile(rb"20\d{2}[-/]\d{2}[-/]\d{2}"),
}


def search_plaintext(data: bytes) -> List[dict]:
    """搜明文特征（中文/JSON/URL/时间戳），返回结构化候选。"""
    hits: List[dict] = []
    for kind, pat in _PLAINTEXT_PATTERNS.items():
        for m in pat.finditer(data):
            content = m.group()
            # 中文候选：过滤掉全是乱码的假阳性
            if kind == "cn_text":
                printable = sum(1 for b in content if 32 <= b < 127)
                if printable < 2:
                    continue
            hits.append({
                "kind": kind,
                "offset": m.start(),
                "content": content[:200].decode("utf-8", "ignore"),
                "length": len(content),
            })
    return hits


# ── key 搜索（6 维校验借鉴 dexripper）─────────────────────────────────────

_KEY_PATTERNS = {
    "hex32": re.compile(rb"(?<![0-9a-fA-F])[0-9a-fA-F]{32}(?![0-9a-fA-F])"),
    "hex64": re.compile(rb"(?<![0-9a-fA-F])[0-9a-fA-F]{64}(?![0-9a-fA-F])"),
    "b64_24": re.compile(rb"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{24}==?(?![A-Za-z0-9+/])"),
    "b64_44": re.compile(rb"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{44}==?(?![A-Za-z0-9+/])"),
}


def _validate_key(value: bytes) -> bool:
    """key 候选的轻量校验（借鉴 dexripper 6 维思想，key 场景做 4 维）：
    1. 长度 ∈ {16,24,32}（AES-128/192/256）
    2. 非全 0 / 全 F
    3. 非纯数字（不太可能是 key）
    4. 字节分布足够散（非重复单字节）
    """
    if len(value) not in (16, 24, 32):
        return False
    if value == b"\x00" * len(value) or value == b"\xff" * len(value):
        return False
    if value.isdigit():
        return False
    if len(set(value)) < len(value) // 2:  # 熵太低
        return False
    return True


def search_key(data: bytes) -> List[dict]:
    """搜 AES key 候选（hex32/64、base64），校验后输出。"""
    hits: List[dict] = []
    for kind, pat in _KEY_PATTERNS.items():
        for m in pat.finditer(data):
            raw = m.group().decode("ascii")
            if kind in ("hex32", "hex64"):
                key = bytes.fromhex(raw)
            else:  # base64
                try:
                    import base64
                    key = base64.b64decode(raw + "=" * (-len(raw) % 4))
                except Exception:
                    continue
            if not _validate_key(key):
                continue
            hits.append({
                "kind": kind,
                "offset": m.start(),
                "value": raw,
                "length": len(key),
            })
    return hits


# ── 主流程 ────────────────────────────────────────────────────────────────

def dump_memory(pid: int, out_dir: str) -> dict:
    """执行非注入 dump + 搜索，返回结构化 findings。"""
    os.makedirs(out_dir, exist_ok=True)
    regions = select_regions(parse_maps(pid))
    dump_path = os.path.join(out_dir, f"dump_{pid}.bin")
    offsets = dump_regions(pid, regions, dump_path)
    print(f"[*] dump 完成: {len(offsets)} 段, {sum(r.size for r, _ in offsets) // 1024} KB")

    # 逐段搜索（记录段来源，供工蚁判断时溯源）
    plaintexts, keys = [], []
    with open(dump_path, "rb") as f:
        for r, off in offsets:
            f.seek(off)
            data = f.read(r.size)
            for h in search_plaintext(data):
                h["region"] = r.path or "anon"
                h["offset_abs"] = r.start + h["offset"]
                plaintexts.append(h)
            for k in search_key(data):
                k["region"] = r.path or "anon"
                k["offset_abs"] = r.start + k["offset"]
                keys.append(k)

    findings = {
        "pid": pid,
        "dump_path": dump_path,
        "regions_dumped": len(offsets),
        "plaintext_candidates": plaintexts,
        "key_candidates": keys,
    }
    with open(os.path.join(out_dir, "findings.json"), "w", encoding="utf-8") as f:
        json.dump(findings, f, ensure_ascii=False, indent=2)
    print(f"[*] 明文候选 {len(plaintexts)} 个, key 候选 {len(keys)} 个 → findings.json")
    return findings


def main(argv: List[str]) -> int:
    if "--pid" in argv:
        pid = int(argv[argv.index("--pid") + 1])
        out_dir = argv[argv.index("--pid") + 2]
    elif len(argv) >= 3:
        package, out_dir = argv[1], argv[2]
        pid = find_pid(package)
        if pid is None:
            print(f"[!] 找不到进程: {package}", file=sys.stderr)
            return 1
    else:
        print(__doc__)
        return 1
    dump_memory(pid, out_dir)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
