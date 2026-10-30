# -*- coding: utf-8 -*-
"""
GFWAirPort → Clash 订阅链接抓取器（GitHub Actions 版）

流程: 发现/使用面板地址 → 登录 → 解析订阅链接 → AES 加密 → docs/sub.enc.json
敏感信息全部来自环境变量（GitHub Secrets），不落盘、不进日志。

必填环境变量:
  PANEL_URL        面板地址，如 https://panel.example.com （登录后浏览器地址栏的域名）
  PANEL_EMAIL      登录邮箱
  PANEL_PASSWORD   登录密码
  ENC_PASSWORD     加密口令（前端解密用，自定义强口令）

可选:
  PANEL_KIND       auto | v2board | sspanel   默认 auto
  ENTRY_URL        镜像入口页，默认 https://ilove.ga/
  OUT_DIR          输出目录，默认 docs

用法:
  python scripts/fetch_sub.py            # 正常抓取
  python scripts/fetch_sub.py --probe    # 只做诊断，不写文件
"""
import json
import os
import re
import sys
from datetime import datetime, timezone, timedelta

import requests

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from crypto_util import encrypt_payload, mask_url  # noqa: E402

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")
TIMEOUT = 25
CST = timezone(timedelta(hours=8))

SUBS_PATTERNS = [
    r"clash://install-config\?url=([^\"'\s<>]+)",
    r"(https?://[^\"'\s<>]*(?:/api/v1/client/subscribe|/api/v1/client/subscribe\?)[^\"'\s<>]*)",
    r"(https?://[^\"'\s<>]*?/subscribe\?token=[A-Za-z0-9]+)",
    r"[\"']?(/link/[A-Za-z0-9]{8,}[^\"'\s<>]*)",
]

log_lines = []


def log(msg):
    print(msg, flush=True)
    log_lines.append(msg)


def new_session():
    s = requests.Session()
    s.headers.update({
        "User-Agent": UA,
        "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
        "Accept": "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8",
    })
    return s


def cf_blocked(r):
    txt = (r.text or "")[:4000].lower()
    return ("just a moment" in txt or "cf-chl" in txt or "challenge-platform" in txt
            or r.headers.get("cf-mitigated") == "challenge")


def fetch(s, url, **kw):
    try:
        r = s.get(url, timeout=TIMEOUT, allow_redirects=True, **kw)
        if cf_blocked(r):
            log(f"  ! {url} 被 Cloudflare 挑战页拦截（HTTP {r.status_code}）")
            return None
        return r
    except Exception as e:
        log(f"  ! 请求失败 {url} → {type(e).__name__}: {str(e)[:120]}")
        return None


# ---------- 面板识别 ----------
def fingerprint(s, base):
    """返回 (kind, 证据)"""
    r = fetch(s, base + "/")
    if r is None:
        return None, "首页不可达"
    html = r.text or ""
    low = html.lower()

    ev = []
    if "v2board" in low or "/api/v1/passport/auth/login" in low:
        ev.append("v2board")
    if "sspanel" in low or "sspanel-uim" in low:
        ev.append("sspanel")
    if "/auth/login" in low:
        ev.append("auth-login")

    # 探测 V2Board 登录接口是否存在
    try:
        rr = s.post(base + "/api/v1/passport/auth/login", json={"email": "probe@example.com", "password": "x"},
                    timeout=TIMEOUT)
        if rr.status_code in (200, 422, 400) or (rr.headers.get("content-type", "").startswith("application/json") and rr.status_code < 500):
            ev.append("v2board-api")
    except Exception:
        pass

    if "v2board" in ev or "v2board-api" in ev:
        return "v2board", ",".join(ev) or "api"
    if "sspanel" in ev:
        return "sspanel", ",".join(ev)
    return "unknown", ",".join(ev) or f"HTTP {r.status_code} len={len(html)}"


# ---------- 镜像发现 ----------
def discover_panels(entry):
    s = new_session()
    r = fetch(s, entry)
    if r is None:
        return []
    text = r.text or ""
    cands = set()
    for m in re.finditer(r"https?://([A-Za-z0-9\.\-]+\.[A-Za-z]{2,})", text):
        host = m.group(1).lower()
        if any(bad in host for bad in (
                "google", "gstatic", "jsdelivr", "cloudflare", "github", "baidu",
                "w3.org", "jquery", "fontawesome", "bootstrapcdn", "unpkg")):
            continue
        cands.add(host)
    log(f"  入口页候选域名 {len(cands)} 个: {', '.join(sorted(cands)[:10]) or '(无，页面为 JS 动态渲染)'}")
    return sorted(cands)


# ---------- 适配器 ----------
def _safe_snip(text, n=170):
    """把响应体截断并脱敏，便于日志排错又不泄露 token/订阅串。"""
    t = re.sub(r"\s+", " ", text or "").strip()
    t = re.sub(r"(token=|token\":\")[A-Za-z0-9_\-]{6,}", r"\1****", t)
    t = re.sub(r"(/link/)[A-Za-z0-9]{6,}", r"\1****", t)
    t = re.sub(r"(subscribe\?)[A-Za-z0-9_\-=]{6,}", r"\1****", t)
    return t[:n]


def _v2_login_token(payload):
    """从登录响应里取 token，兼容 V2Board / Xboard 的几种返回结构。"""
    body = payload.get("data") if isinstance(payload, dict) else None
    if isinstance(body, str) and body:
        return body
    if not isinstance(body, dict):
        return None
    for k in ("token", "auth_data", "authData", "access_token", "accessToken"):
        v = body.get(k)
        if isinstance(v, str) and v:
            return v
        if isinstance(v, dict):
            for kk in ("token", "auth_data"):
                vv = v.get(kk)
                if isinstance(vv, str) and vv:
                    return vv
    return None


def _v2_pick_sub(data, base):
    """从 getSubscribe 的 data 里取订阅链接；取不到就用 token 自行拼。"""
    if not isinstance(data, dict):
        return None
    for k in ("subscribe_url", "subscribeUrl", "subscribe_link", "url"):
        v = data.get(k)
        if isinstance(v, str) and v.startswith("http"):
            return v
    tok = data.get("token")
    if isinstance(tok, str) and len(tok) >= 6:
        return base.rstrip("/") + "/api/v1/client/subscribe?token=" + tok
    return None


def try_v2board(s, base, email, pwd):
    """V2Board / Xboard 适配器。

    登录: POST /api/v1/passport/auth/login  {"email":..,"password":..}
    取订阅: GET /api/v1/user/getSubscribe（带登录 token）

    不同面板对 token 的接受方式不一致（裸 token / Bearer / X-Token），
    这里逐一组合尝试，并把每次的状态码和响应片段写进日志，便于定位 403。
    返回订阅链接字符串，失败返回 None。
    """
    try:
        r = s.post(base + "/api/v1/passport/auth/login",
                   json={"email": email, "password": pwd}, timeout=TIMEOUT)
    except Exception as e:
        log(f"  v2board 登录请求异常 {type(e).__name__}: {str(e)[:100]}")
        return None
    if cf_blocked(r):
        log("  v2board 登录被 Cloudflare 挑战页拦截")
        return None
    if r.status_code != 200:
        log(f"  v2board 登录 HTTP {r.status_code} · {_safe_snip(r.text)}")
        return None
    try:
        j = r.json()
    except Exception:
        log(f"  v2board 登录返回非 JSON · {_safe_snip(r.text, 120)}")
        return None

    token = _v2_login_token(j)
    if not token:
        log(f"  v2board 登录无 token，响应: {_safe_snip(json.dumps(j, ensure_ascii=False))}")
        return None
    log(f"  v2board 登录成功（token {len(token)} 字符）")

    variants = (
        ("裸token", {"Authorization": token}),
        ("Bearer", {"Authorization": "Bearer " + token}),
        ("X-Token", {"X-Token": token}),
    )
    endpoints = ("/api/v1/user/getSubscribe", "/api/v1/user/subscribe")
    seen = []
    for hname, hdr in variants:
        for ep in endpoints:
            try:
                rr = s.get(base + ep, headers=hdr, timeout=TIMEOUT)
            except Exception as e:
                seen.append(f"{hname}{ep}:{type(e).__name__}")
                log(f"    {hname} {ep} → 请求异常 {type(e).__name__}")
                continue
            code = rr.status_code
            snippet = _safe_snip(rr.text)
            log(f"    {hname} {ep} → HTTP {code} · {snippet[:110]}")
            seen.append(f"{hname}{ep}:{code}")
            if code != 200:
                if code == 403 and rr.headers.get("cf-mitigated") == "challenge":
                    log("      ↑ 这是 Cloudflare 挑战，不是账号问题")
                continue
            try:
                data = rr.json().get("data")
            except Exception:
                log("      ↑ 返回非 JSON，跳过")
                continue
            sub = _v2_pick_sub(data, base)
            if sub:
                return sub
            keys = list(data.keys())[:10] if isinstance(data, dict) else type(data).__name__
            log(f"      ↑ 取到数据但没有订阅链接，字段: {keys}")
    log(f"  v2board 全部组合失败: {', '.join(seen)}")
    return None


def try_sspanel(s, base, email, pwd):
    r = fetch(s, base + "/auth/login")
    if r is None:
        return None
    html = r.text or ""
    m = re.search(r'name=["\']csrf_token["\']\s+value=["\']([^"\']+)', html) or \
        re.search(r'value=["\']([^"\']+)["\']\s+name=["\']csrf_token', html)
    token = m.group(1) if m else ""
    if not token:
        log("  sspanel 登录页未找到 csrf_token")
        return None
    rr = s.post(base + "/auth/login",
                data={"email": email, "passwd": pwd, "password": pwd,
                      "csrf_token": token, "login": "1", "remember_me": "on"},
                timeout=TIMEOUT, allow_redirects=True)
    if rr.status_code >= 400:
        log(f"  sspanel 登录 HTTP {rr.status_code}")
        return None
    if "auth/login" in (rr.url or "") and "登录失败" in (rr.text or ""):
        log("  sspanel 登录失败（账号密码错或被风控）")
        return None
    log("  sspanel 登录提交完成")

    for path in ("/user", "/dashboard", "/user/profile", "/user/subscribe"):
        rp = fetch(s, base + path)
        if rp is None:
            continue
        found = extract_sub(rp.text or "", base)
        if found:
            return found
    return None


def extract_sub(html, base):
    for i, pat in enumerate(SUBS_PATTERNS):
        m = re.search(pat, html, re.I)
        if not m:
            continue
        val = m.group(1).replace("&amp;", "&").strip()
        if i == 0:  # clash://install-config?url=xxx
            try:
                from urllib.parse import unquote
                val = unquote(val)
            except Exception:
                pass
        elif val.startswith("/"):
            val = base.rstrip("/") + val
        if len(val) > 20 and ("http" in val or val.startswith("/link/")):
            return val if val.startswith("http") else base.rstrip("/") + val
    return None


def generic_scan(s, base, email, pwd):
    """登录后把常见页面全扫一遍找订阅链接"""
    for path in ("/user", "/dashboard", "/", "/user/subscribe", "/user/profile"):
        r = fetch(s, base + path)
        if r and r.status_code == 200:
            got = extract_sub(r.text or "", base)
            if got:
                log(f"  在 {path} 页命中订阅链接")
                return got
    return None


# ---------- 域名归一化 ----------
def normalize_url(u, keep_path=False):
    """中文域名(IDN) → punycode，补协议、去尾斜杠。

    例: 翻墙机场.com → https://xn--mest5a943ag8x.com
    requests 虽能处理 unicode host，但 Actions 环境差异较大，统一转 ascii 最稳。
    keep_path=False 时丢弃路径（面板 URL 只需 scheme+host，带 /user 之类会让拼接 404）。
    """
    u = (u or "").strip()
    if not u:
        return ""
    if not u.startswith(("http://", "https://")):
        u = "https://" + u
    try:
        from urllib.parse import urlsplit, urlunsplit

        parts = urlsplit(u)
        host = parts.hostname or ""
        netloc = host
        if host and any(ord(c) > 127 for c in host):
            try:
                import idna

                ascii_host = idna.encode(host).decode("ascii")
            except Exception:
                ascii_host = host.encode("idna").decode("ascii")
            netloc = ascii_host
            log(f"  · 中文域名已转 punycode: {host} → {ascii_host}")
        if parts.port:
            netloc += f":{parts.port}"
        path = parts.path if keep_path else ""
        if path == "/":
            path = ""
        u = urlunsplit((parts.scheme, netloc, path, parts.query if keep_path else "", ""))
    except Exception as e:
        log(f"  ! 域名归一化失败（继续用原值）: {type(e).__name__}: {e}")
    return u.rstrip("/")


# ---------- 主流程 ----------
def main():
    probe_only = "--probe" in sys.argv
    panel = normalize_url(os.environ.get("PANEL_URL"))
    email = (os.environ.get("PANEL_EMAIL") or "").strip()
    pwd = os.environ.get("PANEL_PASSWORD") or ""
    enc_pwd = os.environ.get("ENC_PASSWORD") or ""
    kind = (os.environ.get("PANEL_KIND") or "auto").strip().lower()
    entry = normalize_url(os.environ.get("ENTRY_URL") or "https://ilove.ga/", keep_path=True)
    out_dir = os.environ.get("OUT_DIR") or "docs"

    log(f"=== GFWAirPort 订阅同步 {datetime.now(CST).isoformat(timespec='seconds')} ===")

    if not panel:
        log("[1] 未配置 PANEL_URL，尝试从入口页发现镜像…")
        hosts = discover_panels(entry)
        if not hosts:
            log("!! 无法自动发现面板地址。请在 Secrets 里设置 PANEL_URL（登录后地址栏的域名）")
            write_status(out_dir, False, "未配置 PANEL_URL 且入口页无可解析域名")
            return 1
        panel = normalize_url("https://" + hosts[0])
        log(f"    暂用候选: {panel}")

    log(f"[2] 目标面板: {panel}")
    s = new_session()

    detected, evidence = fingerprint(s, panel)
    log(f"    面板识别: {detected}  证据: {evidence}")
    if detected == "unknown" and kind == "auto":
        log("    ! 未识别出面板类型，仍将尝试全部适配器")

    if not email or not pwd:
        log("!! 缺少 PANEL_EMAIL / PANEL_PASSWORD")
        write_status(out_dir, False, "缺少登录凭据环境变量")
        return 1

    if probe_only:
        log("[3] 诊断模式：尝试登录并检查能否看到订阅页（不写文件）")
        sub = None
        for name, fn in (("v2board", try_v2board), ("sspanel", try_sspanel)):
            if kind != "auto" and kind != name:
                continue
            log(f"  → 尝试 {name}")
            sub = fn(s, panel, email, pwd)
            if sub:
                log(f"    命中: {mask_url(sub)}")
                break
        if not sub:
            sub = generic_scan(s, panel, email, pwd)
            log("  → 通用扫描: " + (mask_url(sub) if sub else "无"))
        log("=== 诊断结束 ===")
        return 0 if sub else 2

    if not enc_pwd or len(enc_pwd) < 8:
        log("!! ENC_PASSWORD 缺失或过短（至少 8 位）")
        write_status(out_dir, False, "ENC_PASSWORD 缺失或过短")
        return 1

    log("[3] 登录并抓取订阅链接")
    sub = None
    ok_kind = None
    order = ["v2board", "sspanel"] if kind == "auto" else [kind]
    for name in order:
        fn = {"v2board": try_v2board, "sspanel": try_sspanel}.get(name)
        if not fn:
            continue
        log(f"  → {name}")
        sub = fn(s, panel, email, pwd)
        if sub:
            ok_kind = name
            break
    if not sub:
        log("  → 通用扫描兜底")
        sub = generic_scan(s, panel, email, pwd)
        ok_kind = ok_kind or "generic"

    if not sub or not re.match(r"^https?://", sub):
        log("!! 未能取到有效的订阅链接")
        write_status(out_dir, False, f"未取到订阅链接（面板识别={detected}）")
        return 1

    log(f"[4] 成功: {mask_url(sub)}  (适配器={ok_kind})")

    blob = encrypt_payload(enc_pwd, {
        "sub": sub,
        "kind": ok_kind,
        "panel": panel,
        "fetched_at": datetime.now(CST).isoformat(timespec="seconds"),
    })
    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, "sub.enc.json"), "w", encoding="utf-8") as f:
        json.dump(blob, f, ensure_ascii=False, indent=2)
    log(f"[5] 已写入 {out_dir}/sub.enc.json（AES-256-GCM 加密，updated={blob['updated']}）")
    write_status(out_dir, True, f"抓取成功（{ok_kind}）", blob["updated"])
    return 0


def write_status(out_dir, ok, message, updated=""):
    os.makedirs(out_dir, exist_ok=True)
    status = {
        "ok": ok,
        "message": message,
        "updated": updated or datetime.now(CST).isoformat(timespec="seconds"),
        "run_at": datetime.now(CST).isoformat(timespec="seconds"),
        "log": log_lines[-12:],
    }
    with open(os.path.join(out_dir, "status.json"), "w", encoding="utf-8") as f:
        json.dump(status, f, ensure_ascii=False, indent=2)


if __name__ == "__main__":
    sys.exit(main())
