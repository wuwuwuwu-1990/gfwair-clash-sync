# gfwair-clash-sync

把翻墙机场面板里的 Clash 订阅链接，用 GitHub Actions 定时抓取 → 加密 → 公开发布，
再由本地软件「翻墙机场导入 Clash 便捷系统 v1.1.1」自动拉取解密并填入。

**仓库公开也安全**：仓库里只有 AES-256-GCM 密文，没有口令、没有明文订阅链接。

---

## 一、它是怎么跑的

```
GitHub Actions（每天 07:00 北京，境外 IP）
   └─ 登录面板 → 解析订阅链接 → AES-256-GCM 加密
        └─ 提交 docs/sub.enc.json（密文）
             └─ 本地软件 fetch → Web Crypto 解密 → 填入订阅 → 一键导入 Clash
```

- 抓取在 **Actions** 上完成，不需要你的电脑开机
- 只有**你的机器**能解密，因为口令只存在你手里和浏览器的 localStorage
- 抓取失败时**不覆盖**上一份 `sub.enc.json`，旧链接继续可用

---

## 二、部署步骤

### 1. 建仓库

新建一个仓库，**必须选 Public**（jsDelivr 与 Pages 免费版都只能读公开仓库；里面只有密文，公开无风险）。
仓库名建议就用 `gfwair-clash-sync`，分支 `main`。
把本目录的 `.github/`、`scripts/`、`docs/` 全部上传。

### 2. 配置 Secrets

仓库 → Settings → Secrets and variables → Actions → New repository secret：

| Name | 值 | 说明 |
|---|---|---|
| `PANEL_URL` | `https://你的面板域名` | **必填**。登录后浏览器地址栏的域名（ilove.ga 只是镜像入口页，真实面板在镜像域名下） |
| `PANEL_EMAIL` | `你的登录邮箱` | 必填 |
| `PANEL_PASSWORD` | `你的登录密码` | 必填 |
| `ENC_PASSWORD` | 自定的强口令，≥12 位 | 必填。本地软件解密要用**一模一样**的这个 |
| `PANEL_KIND` | `auto` / `v2board` / `sspanel` | 可选，默认 `auto` 自动识别 |

### 3. 先跑一次诊断（推荐）

Actions → 左侧 `sync-sub` → Run workflow，**但在跑之前先本地诊断一次**能省很多时间：

```bash
pip install requests cryptography
PANEL_URL=https://你的面板域名 \
PANEL_EMAIL=你的邮箱 \
PANEL_PASSWORD=你的密码 \
python scripts/fetch_sub.py --probe
```

`--probe` 只诊断不写文件，会打印：面板类型识别结果、登录是否成功、订阅链接是否命中（脱敏显示）。

- 输出 `命中: https://...` → 一切正常，直接跑正式流程
- 输出 `v2board 登录 HTTP 403` / `被 Cloudflare 挑战页拦截` → 面板开了防护，Actions 的 Azure IP 大概率也过不去，见下方「已知限制」

### 4. 拿到数据地址（不用开 Pages）

约定：仓库名设为 `gfwair-clash-sync`，分支 `main`。**默认走 jsDelivr，国内可直连、无需开 Pages、无需等构建**：

```
https://cdn.jsdelivr.net/gh/<用户名>/gfwair-clash-sync@main/docs/sub.enc.json
```

> 实测：`cdn.jsdelivr.net` 返回 `200` + `access-control-allow-origin: *`，网页可直接跨域 fetch；
> `raw.githubusercontent.com` 国内多数网络直连超时，**不建议填**。

如果想用 GitHub Pages（需 public 仓库，构建约 1 分钟）：

Settings → Pages → Source 选 `Deploy from a branch` → Branch `main` / 目录 `/docs` → Save，地址为：

```
https://<用户名>.github.io/gfwair-clash-sync/sub.enc.json
```

注意 Pages 源选 `/docs` 时地址里**不含 `docs`**（docs 目录就是站点根）。

### 5. 填进软件

打开「翻墙机场导入 Clash 便捷系统 v1.1.1」→「云端自动同步」卡片：

- 加密数据地址：上面的 jsDelivr URL
- 解密口令：`ENC_PASSWORD` 的同一个值
- 勾上「到期时自动从云端同步」
- 点「立即同步」验证一次

看到绿色「成功 · 已更新订阅」即完成。

> jsDelivr 会缓存分支地址（约 12 小时）。若确认 Actions 已成功但页面还是旧数据，访问一次
> `https://purge.jsdelivr.net/gh/<用户名>/gfwair-clash-sync@main/docs/sub.enc.json` 强制刷新缓存。

---

## 三、已知限制（务必先读）

1. **云厂商 IP 可能被面板屏蔽**
   Actions 跑在 Azure 的 IP 段上。有些机场为了防白嫖，会对 IDC/云 IP 段做限制或直接弹 Cloudflare 挑战。
   这是本方案最大的不确定因素，`--probe` 能提前暴露。

2. **定时任务可能延迟**
   GitHub 的 `schedule` 在高峰期会延迟几分钟到几十分钟，不保证准点。对本用途影响可忽略。

3. **仓库 60 天无提交会自动停用 schedule**
   出现提示时进 Actions 点一次 Run workflow 即可恢复（每次有提交也会自动重置）。

4. **cron 用的是 UTC**
   `.github/workflows/sync-sub.yml` 里现在是 `0 23 * * *` = 北京时间每天 07:00。
   之所以每天跑而不是严格隔天：`*/2` 在月末会跳日，每天刷一次更保险，反正前端按「隔一天」提醒导入。

5. **不要在仓库里放主程序 html**
   软件内置了机场账号密码，公开即泄露。`docs/` 下只允许有 `index.html`（本说明页）、`sub.enc.json`、`status.json`。

6. **口令泄露 = 全盘皆输**
   `ENC_PASSWORD` 一旦泄露，谁都能解开你仓库里的订阅链接（等于白嫖你的流量）。用长口令，别复用。

---

## 四、文件说明

| 路径 | 作用 |
|---|---|
| `.github/workflows/sync-sub.yml` | 定时任务定义 |
| `scripts/fetch_sub.py` | 登录面板、解析订阅、加密输出；`--probe` 为诊断模式 |
| `scripts/crypto_util.py` | PBKDF2 + AES-256-GCM 加解密，与前端 Web Crypto 互通 |
| `docs/sub.enc.json` | 密文（由 Actions 生成，不要手改） |
| `docs/status.json` | 最近一次运行结果（明文，不含敏感信息） |
| `docs/index.html` | 仓库落地页，仅说明用途 |

---

## 五、本地自检

```bash
python scripts/crypto_util.py selftest "任意口令"
```

应输出「自检通过」。这一步只验证加解密链路，不联网。
