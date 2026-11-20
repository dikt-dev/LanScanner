#requires -version 3
# 生成 LanScanner 发布包：release\ 目录 + LanScanner-v<日期>.zip
# 用法：powershell -NoProfile -ExecutionPolicy Bypass -File make-release.ps1

$ErrorActionPreference = 'Stop'
$root = $PSScriptRoot
if (-not $root) { $root = (Get-Location).Path }

$exeSrc = Join-Path $root 'LanScanner.exe'
$mdSrc  = Join-Path $root 'LanScanner.md'
foreach ($p in @($exeSrc, $mdSrc)) {
  if (-not (Test-Path -LiteralPath $p)) {
    Write-Host ('[ERROR] 缺少 ' + (Split-Path -Leaf $p) + '，请先运行 build.cmd') -ForegroundColor Red
    exit 1
  }
}

$nl = [string][char]13 + [char]10
$release = Join-Path $root 'release'
if (Test-Path -LiteralPath $release) { Remove-Item -LiteralPath $release -Recurse -Force }

$stage = Join-Path $env:TEMP ('lanscanner-stage-' + [Guid]::NewGuid().ToString('N').Substring(0, 8))
$pkg = Join-Path $stage 'LanScanner'
New-Item -ItemType Directory -Path $pkg -Force | Out-Null

# ---------- 二进制与文档 ----------
Copy-Item -LiteralPath $exeSrc -Destination $pkg
Copy-Item -LiteralPath $mdSrc  -Destination $pkg
$uiPng = Join-Path $root 'LanScanner-ui.png'
if (Test-Path -LiteralPath $uiPng) { Copy-Item -LiteralPath $uiPng -Destination $pkg }

# ---------- 辅助脚本：全部 ASCII，避免任何代码页 / BOM 问题 ----------
$ascii = New-Object System.Text.UTF8Encoding($false)
$unlockLines = @(
  '@echo off',
  'cd /d "%~dp0"',
  'echo.',
  'echo   [1/2] Removing the mark "this file came from the Internet" (Unblock-File) ...',
  'powershell -NoProfile -ExecutionPolicy Bypass -Command "Get-ChildItem -LiteralPath . -Recurse -File | Unblock-File; exit 0"',
  'echo.',
  'echo   [2/2] Done. Now double-click 2-start.cmd  (or LanScanner.exe).',
  'echo.',
  'pause'
)
[System.IO.File]::WriteAllText((Join-Path $pkg '1-unblock-first.cmd'), ($unlockLines -join $nl), $ascii)

$startLines = @(
  '@echo off',
  'cd /d "%~dp0"',
  'start "" "LanScanner.exe"'
)
[System.IO.File]::WriteAllText((Join-Path $pkg '2-start.cmd'), ($startLines -join $nl), $ascii)

# ---------- 中文说明：UTF-8 带 BOM，记事本可直接读 ----------
$utf8bom = New-Object System.Text.UTF8Encoding($true)
$readmeLines = @(
  'LanScanner  局域网设备扫描器',
  ('打包日期：' + (Get-Date).ToString('yyyy-MM-dd')),
  '',
  '============================================================',
  '一、第一次使用（务必按顺序）',
  '============================================================',
  '  1) 先双击  1-unblock-first.cmd   —— 清除文件上的“来自 Internet”标记。',
  '  2) 再双击  2-start.cmd          —— 启动程序（也可以直接双击 LanScanner.exe）。',
  '',
  '  在“扫描范围”里填网段，例如  192.168.0.0/16  或  192.168.1.1-254  ，按 Ctrl+Enter 开始。',
  '',
  '============================================================',
  '二、如果仍弹出“Windows 已保护你的电脑”',
  '============================================================',
  '  点【更多信息】——只有点了它，才会出现【仍要运行】——再点【仍要运行】。',
  '  这是系统对所有“没有代码签名的新程序”的通用提示，不代表程序有问题。',
  '  程序没有联网能力、不上传任何数据，见第三节。',
  '',
  '============================================================',
  '三、这个程序做了什么（可以放心用）',
  '============================================================',
  '  - 纯本地：不联网、不上传数据、不写注册表；设置只存在 %APPDATA%\LanScanner\settings.ini',
  '  - 单文件 exe，运行在系统自带的 .NET Framework 4.x 上（Win7 SP1 及以上免安装）',
  '  - 扫描原理：并发 ICMP 探测 + 合并本机 ARP 邻居表；跨网段设备按本机路由表判路径',
  '  - 扫满 192.168.0.0/16（65534 个地址）约 70 秒，结果可导出 CSV',
  '',
  '============================================================',
  '四、为什么会被 SmartScreen 拦',
  '============================================================',
  '  Windows 只对“有代码签名证书”的程序显示已验证发布者。本程序未购买证书，',
  '  且文件是从网上传过来的（带 Zone.Identifier 标记），SmartScreen 就按',
  '  “未知发布者 + 零信誉”给了蓝色提示。用 1-unblock-first.cmd 清掉标记后，',
  '  绝大多数机器上就不再提示；没清的机器按第二节点【仍要运行】即可。',
  '',
  '  注意：自己做的“自签名证书”对别人的电脑无效（对方不信任你的根证书），',
  '  那种方案只会把提示从“未知发布者”变成“证书不受信任”，不要用。',
  '',
  '============================================================',
  '五、常见问题',
  '============================================================',
  '  Q: 提示“此应用无法在你的电脑上运行”？',
  '  A: 需要 .NET Framework 4.x（Win7 SP1 / 8 / 10 / 11 都自带）。Win7 未装 SP1 需先装 .NET 4。',
  '  Q: 结果里有些设备的 MAC / 厂商是空的？',
  '  A: 那些设备不在本机同二层网段（要过网关），ARP 拿不到 MAC，属正常。',
  '  Q: 杀毒软件报毒？',
  '  A: 未签名 exe 常被启发式误报。可用本机源码 + build.cmd 自己编译一份完全相同的 exe。',
  '',
  '============================================================',
  '六、卸载',
  '============================================================',
  '  绿色程序：删掉整个文件夹即可；如想连设置一起清掉，再删 %APPDATA%\LanScanner。'
)
[System.IO.File]::WriteAllText((Join-Path $pkg 'readme-first.txt'), ($readmeLines -join $nl), $utf8bom)

# ---------- 落到 release\ ----------
New-Item -ItemType Directory -Path $release -Force | Out-Null
Copy-Item -Path (Join-Path $pkg '*') -Destination $release -Recurse -Force

# ---------- 打包 zip ----------
$zipPath = Join-Path $release ('LanScanner-v' + (Get-Date).ToString('yyyyMMdd') + '.zip')
Compress-Archive -Path $pkg -DestinationPath $zipPath -Force
Remove-Item -LiteralPath $stage -Recurse -Force

# ---------- 清单 ----------
Write-Host ''
Write-Host '=== release 目录 ===' -ForegroundColor Cyan
Get-ChildItem -LiteralPath $release | Sort-Object Name | ForEach-Object {
  $kb = ([string]([math]::Round($_.Length / 1KB, 1))).PadLeft(9)
  Write-Host ('  ' + $_.Name.PadRight(30) + ' ' + $kb + ' KB')
}
Write-Host ''
Write-Host ('发布包已生成：' + $zipPath) -ForegroundColor Green
Write-Host '发给别人时只发这个 zip：对方解压后先跑 1-unblock-first.cmd，再跑 2-start.cmd。' -ForegroundColor Green
exit 0