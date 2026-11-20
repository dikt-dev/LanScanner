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

**已完成**：https://github.com/dikt-dev/LanScanner （公开、MIT、`main` 已推送，本地 HEAD 与远端一致）。

推送前确认不要带上：`release\`（生成的包）、`bin\`/`obj\`、你自己的 `settings.ini`。建议加 `.gitignore`。

### 2. 确认 CI 能跑通

打开仓库的 **Actions → build**，确认 `Compile with csc` 与 `Smoke test` 都绿。这一步同时证明「CI 能从源码构建出 exe」，
是 SignPath 审核看的核心材料。

> 已跑通的两次（可作为审核材料直接引用）：
> `runs/44676953832`（提交 8028ec7）与 `runs/44677086943`（提交 47b58cd）→ 均 conclusion **success**，
> 五步全绿（Set up job / Checkout / Compile with csc / Smoke test / Upload unsigned artifact），
> 产出 artifact `unsigned-lanscanner`（约 35 KB，内含 `LanScanner.exe`）。

### 2.5 控制台那几格是干什么的（先分清两条路）

你在 `app.signpath.io` 看到的是**试用订阅的控制台**（左侧 Projects / Certificates / Signing Requests）。
这里能做全部配置，但**免费给开源项目的那张证书不从这里申请**——免费通道是 SignPath Foundation，
入口 `https://signpath.org/apply`。两者关系：控制台 = 生产线，基金会 = 发证机关。
所以最省时间的做法是：**先把生产线装好、用自签证书跑通一遍**，等基金会批下来只换证书和策略名。

截图里四格对应：

| 引导格 | 含义 | 你现在该做什么 |
|---|---|---|
| Create test certificate | 自签 X.509，**只能测试** | 可以建，用来跑通管线；发给别人没有任何好处（对方机器不信任它） |
| Create your first project | 建项目、绑定 GitHub 仓库 | 建 `lanscanner`，绑定 `dikt-dev/LanScanner` |
| Add a policy for test signing | 签名策略：谁触发、要不要人工批准 | 建 `test-signing`，放开 GitHub connector |
| Sign an artifact | 真正出签名 | 推一次代码，看产物变成 `signed-lanscanner` |

### 2.6 自测的点击顺序（约 20 分钟，不用等审核）

1. **Create project**：名字 `LanScanner`，slug `lanscanner`；
2. 项目里 → *Trusted build systems* → 加 **GitHub**，填 `dikt-dev/LanScanner`；
3. 项目里 → *Signing policies* → 新建 `test-signing`，勾上刚加的 GitHub connector，批准方式选自动（自己的项目）；
4. 项目里 → *Artifact configurations* → 新建 `lanscanner`：
   - 根元素选 **`<zip-file>`**——`upload-artifact` 默认把文件打成一个 zip，SignPath 收到的就是这个 zip；
   - 里面套一层 `<pe-file>`，`path` 写 `LanScanner.exe`；
5. *Certificates* → 按第一格建自签证书，并在 `test-signing` 里选用它；
6. 记下 **organization id**（组织设置页，GUID 形式）和 **project slug**（`lanscanner`）；
7. 个人头像 → *API tokens* → 建 token（scope 选该 project），填进 GitHub 仓库 Secrets：`SIGNPATH_ORG_ID`、`SIGNPATH_API_TOKEN`；
8. 把 `.github/workflows/build.yml` 末尾注释的两步取消注释，`signing-policy-slug` 先填 `test-signing`，推一次；
9. 下载 `signed-lanscanner`，`signtool verify /pa /v LanScanner.exe` 会通过，但证书不受信任——这是测试签名的正常现象。

基金会批下来后：`signing-policy-slug` 改回 `release-signing`、`project-slug` 换成基金会给的项目，其余不动。

### 3. 提交申请

1. 访问 `https://signpath.org/` → **Apply**（或 `https://signpath.org/apply`）；
2. 填写：仓库 URL、许可证（MIT）、项目简介（做什么、谁用、为什么需要签名）、截图（用 `LanScanner-ui.png`）、维护者联系方式；
3. 等审核（人工，通常数天到数周，无 SLA）。

### 4. 审核通过后接通签名

1. 在 SignPath 后台确认 **organization / project / signing policy / artifact configuration** 四样齐全（2.6 节已建好），记下 `organization-id`、`project-slug`、`signing-policy-slug`、`artifact-configuration-slug`；
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
