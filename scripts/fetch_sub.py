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


def _v2_cands(payload):
    """从登录响应里收集"可能是鉴权 token"的字符串，按可信度排序。

    V2Board 系面板的 data 里常见字段：auth_data / token / expire_in。
    其中只有 auth_data（或部分版本的 token）是会话凭据，另一个往往是**订阅 token**，
    两者长度可能都是 32，混用就会拿到 "未登录或登陆已过期"。
    """
    body = payload.get("data") if isinstance(payload, dict) else None
    items = []
    if isinstance(body, str):
        items.append(("data", body))
    elif isinstance(body, dict):
        for k in ("auth_data", "authData", "token", "access_token", "accessToken", "session"):
            v = body.get(k)
            if isinstance(v, str) and 16 <= len(v) <= 300:
                items.append((k, v))
        for k, v in body.items():
            if isinstance(v, str) and 24 <= len(v) <= 300 and re.fullmatch(r"[A-Za-z0-9_.\-|=+/]+", v):
                items.append((k, v))
    seen, out = set(), []
    for k, v in items:
        if v in seen:
            continue
        seen.add(v)
        out.append((k, v))
    return out[:3]


def looks_like_sub(r):
    """判断响应是否真的是一份订阅（yaml / base64 节点 / 带 subscription-userinfo 头）。"""
    if r is None or r.status_code != 200:
        return False
    if "subscription-userinfo" in str(r.headers).lower():
        return True
    head = r.content[:2000]
    txt = head.decode("utf-8", "ignore")
    if "proxies:" in txt or "proxy-groups:" in txt:
        return True
    if any(p in txt for p in ("ss://", "vmess://", "trojan://", "vless://", "hysteria")):
        return True
    try:
        import base64 as _b64

        pad = txt.strip().replace("\n", "")
        dec = _b64.b64decode(pad[:1200] + "=" * (-len(pad[:1200]) % 4)).decode("utf-8", "ignore")
        if any(p in dec for p in ("ss://", "vmess://", "trojan://", "vless://")):
            return True
    except Exception:
        pass
    return False


def _v2_try_api(s, base, cands):
    """用若干「凭据值 × 传递方式」组合去调 getSubscribe，命中返回订阅链接。"""
    forms = (
        ("头 Authorization", lambda v: {"headers": {"Authorization": v}}),
        ("头 Authorization+Bearer", lambda v: {"headers": {"Authorization": "Bearer " + v}}),
        ("参数 auth_data", lambda v: {"params": {"auth_data": v}}),
    )
    tried = []
    for cname, cval in cands:
        for fname, mk in forms:
            try:
                rr = s.get(base + "/api/v1/user/getSubscribe", timeout=TIMEOUT, **mk(cval))
            except Exception as e:
                tried.append(f"{cname}/{fname}:{type(e).__name__}")
                log(f"    {cname} · {fname} → 异常 {type(e).__name__}")
                continue
            code = rr.status_code
            tried.append(f"{cname}/{fname}:{code}")
            if code == 200:
                try:
                    data = rr.json().get("data")
                except Exception:
                    data = None
                sub = _v2_pick_sub(data, base)
                if sub:
                    log(f"    {cname} · {fname} → HTTP 200 ✓")
                    return sub
                keys = list(data.keys())[:10] if isinstance(data, dict) else type(data).__name__
                log(f"    {cname} · {fname} → HTTP 200 但无订阅字段: {keys}")
            else:
                log(f"    {cname} · {fname} → HTTP {code} · {_safe_snip(rr.text, 90)}")
    log(f"  v2board 接口组合均未成: {'; '.join(tried)}")
    return None


def _v2_try_build(s, base, cands):
    """直接用候选 token 拼订阅地址并验证——绕开 getSubscribe 的鉴权问题。

    V2Board 订阅地址格式固定：{base}/api/v1/client/subscribe?token=<订阅token>
    只要登录响应里带了这个 token，即便会话鉴权对不上也能拿到可用链接。
    """
    for cname, cval in cands:
        url = base.rstrip("/") + "/api/v1/client/subscribe?token=" + cval
        try:
            rr = s.get(url, timeout=TIMEOUT)
            ok = looks_like_sub(rr)
            if not ok:
                # 部分面板只给 Clash UA 下发节点列表，换 UA 再试一次
                rr2 = s.get(url, timeout=TIMEOUT, headers={"User-Agent": "clash-verge/v2.0.0"})
                if looks_like_sub(rr2):
                    rr, ok = rr2, True
        except Exception as e:
            log(f"    拼接探测 {cname} → 异常 {type(e).__name__}")
            continue
        log(f"    拼接探测 {cname} → HTTP {rr.status_code}{' ✓ 是订阅内容' if ok else ' 不是订阅'}")
        if ok:
            return url
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

    两条独立通路，任一成功即返回：
      A. 直接拼订阅地址（用登录响应里的 token 探测），不看会话鉴权
      B. 调 /api/v1/user/getSubscribe（凭据值 × 传递方式 共 9 组）
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

    body = j.get("data") if isinstance(j, dict) else None
    shape = (f"{k}({len(v)})" for k, v in body.items() if isinstance(v, str)) if isinstance(body, dict) else []
    log(f"  v2board 登录响应字段: {', '.join(shape) or type(body).__name__}")

    cands = _v2_cands(j)
    if not cands:
        log(f"  v2board 登录未取到可用 token · {_safe_snip(json.dumps(j, ensure_ascii=False))}")
        return None
    log(f"  v2board 登录成功，候选凭据: {', '.join(f'{k}({len(v)})' for k, v in cands)}")

    log("  [3a] 直接拼接订阅地址探测")
    sub = _v2_try_build(s, base, cands)
    if sub:
        log("  [3a] 命中，无需再走接口鉴权")
        return sub

    log("  [3b] 调取订阅接口（多组合）")
    sub = _v2_try_api(s, base, cands)
    if sub:
        return sub
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
    try:
        sys.exit(main())
    except SystemExit:
        raise
    except BaseException as e:  # 任何意外都要落 status.json，否则失败原因只能翻 Actions 日志
        import traceback

        traceback.print_exc()
        log(f"!! 未捕获异常 {type(e).__name__}: {str(e)[:160]}")
        try:
            write_status(os.environ.get("OUT_DIR") or "docs", False,
                         f"脚本异常 {type(e).__name__}: {str(e)[:120]}")
        except Exception:
            pass
        sys.exit(1)
