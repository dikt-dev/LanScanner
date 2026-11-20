# 用 SignPath Foundation 免费给 LanScanner 签名（申请指南）

SignPath Foundation 给**开源项目**免费签发代码签名证书。证书签在基金会名下（发布者显示 «SignPath Foundation»），
他们核实「这个 exe 确实是从你的公开仓库构建出来的」，然后用自己的 HSM 里的私钥签名。
对你的意义：不必买证书、不必自己保管私钥，就能拿到一个浏览器/资源管理器里「已验证发布者」的 exe。

## 前提条件（缺一不可）

| 条件 | 本仓库现状 |
|---|---|
| 代码在**公开** GitHub 仓库 | 需你推送（本目录已就绪） |
| OSI 认可的开源许可证 | 已放 `LICENSE`（MIT） |
| 二进制由**持续集成**从该仓库构建 | 已放 `.github/workflows/build.yml`（windows-latest + csc） |
| 项目真实可用（不是玩具/一次性脚本） | 有完整功能、文档、截图 |

> 私有仓库、只给内网用的工具不符合条件；不想开源就别走这条路，用「便携包 + 一键解锁」或付费签名。

## 步骤

### 1. 把代码推到公开仓库

```
git remote add origin https://github.com/dikt-dev/LanScanner.git
git push -u origin main
```

（本目录已经是 git 仓库、分支 `main`、首次提交已完成）

推送前确认不要带上：`release\`（生成的包）、`bin\`/`obj\`、你自己的 `settings.ini`。建议加 `.gitignore`。

### 2. 确认 CI 能跑通

打开仓库的 **Actions → build**，确认 `Compile with csc` 与 `Smoke test` 都绿。这一步同时证明「CI 能从源码构建出 exe」，
是 SignPath 审核看的核心材料。

> 已跑通的一次（可作为审核材料直接引用）：
> `https://github.com/dikt-dev/LanScanner/actions/runs/44676953832` → conclusion **success**，
> 五步全绿（Set up job / Checkout / Compile with csc / Smoke test / Upload unsigned artifact），
> 产出 artifact `unsigned-lanscanner`（约 35 KB，内含 `LanScanner.exe`）。

### 3. 提交申请

1. 访问 `https://signpath.org/` → **Apply**（或 `https://signpath.org/apply`）；
2. 填写：仓库 URL、许可证（MIT）、项目简介（做什么、谁用、为什么需要签名）、截图（用 `LanScanner-ui.png`）、维护者联系方式；
3. 等审核（人工，通常数天到数周，无 SLA）。

### 4. 审核通过后接通签名

1. 在 SignPath 后台创建 **organization / project / signing policy**，记下 `organization-id`、`project-slug`、`signing-policy-slug`；
2. 在 GitHub 仓库 **Settings → Secrets and variables → Actions** 添加 `SIGNPATH_ORG_ID`、`SIGNPATH_API_TOKEN`；
3. 把 `.github/workflows/build.yml` 里被注释的两步取消注释，把 `project-slug` / `signing-policy-slug` 换成真实值；
4. 打 tag 触发：`git tag v1.0.0 && git push origin v1.0.0`；
5. 下载 `signed-lanscanner` 产物，本地验证：

```
signtool verify /pa /v LanScanner.exe
(Get-AuthenticodeSignature .\LanScanner.exe) | Format-List Status, SignerCertificate
```

应看到 `Status: Valid`、`SignerCertificate.Subject` 里含 SignPath Foundation。

### 5. 发布

把签名后的 exe 放进 GitHub Release，并把 `make-release.ps1` 改成优先取签名产物（`release\` 里的解锁脚本仍保留，
给那些从网盘/微信转发的副本用）。

## 常见误解

- **「签名后 100% 不弹」**：不成立。标准证书的信誉要累积，新文件仍可能被拦；EV 证书才即时信誉。
- **「自签名也一样」**：不一样，自签名对别人的机器只会更糟（证书不受信任）。
- **「本地编译的 exe 可以手动上传签名」**：不行，SignPath 的私钥在 HSM 里，必须走他们的 CI 集成。
