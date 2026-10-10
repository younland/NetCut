# NetCut ✂️

一键断网，尽在指尖。

基于 Rust + GPUI 的 Windows 网络开关工具。常驻系统托盘，单击图标即刻切断/恢复网络连接，告别繁琐的命令行操作。

## 核心特性

- ⚡ **秒级切换** — 一键禁用/启用所有网络适配器
- 🎯 **智能检测** — 自动识别当前连接状态，图标实时反馈
- 🛡️ **自动提权** — 智能请求 UAC 管理员权限
- 🖥️ **原生体验** — GPUI 渲染的现代化界面，深色主题
- 📌 **托盘常驻** — 不占任务栏，随时可用

## 技术栈

Rust · GPUI(gpui-kit) · Windows API · tray-icon

## 构建与运行

要求：Rust 1.92+（MSVC 工具链）、Visual Studio 2022 C++ 构建工具、CMake（见 [gpui-kit 安装文档](https://gpui-kit.com/docs/installation/)）。

```bash
cargo run           # 开发运行（依赖已按文档加 dev profile 优化）
cargo run --release # 发布构建
```

启动时若未以管理员身份运行，会自动弹出 UAC 请求提权。

## 打包发布

需要 [Inno Setup](https://jrsoftware.org/isdown.php)（`winget install JRSoftware.InnoSetup`）。任选一种方式打包：

```bat
build\package.bat
```

```powershell
powershell -ExecutionPolicy Bypass -File build\package.ps1
```

两个脚本等价（release 构建 + 调用 ISCC 编译 `installer\netcut.iss`），安装包输出到 `dist\NetCut-<版本>-setup.exe`。安装器支持桌面快捷方式选项和开机自启（计划任务方式，登录免 UAC 弹窗）。

## 使用

- **托盘图标左键**：打开主窗口；**右键**：弹出功能菜单（主窗口 / 退出）
- **一键断网 / 一键联网**：底部主按钮，禁用或启用所有网卡（按钮文字随当前连接状态变化）
- **网卡选择**：主界面用下拉框选择网卡（按有线/无线/VPN/蓝牙分组，支持搜索），选中后显示该网卡的 IP、子网掩码、默认网关、DNS，并可就地断开/连接
- **局域网模式**：底部按钮一键对所有网卡生效（显示"已关闭/已开启"）——通过 Windows 过滤平台（WFP）在每张网卡上挂一组过滤器：只放行本网段、本地链路（169.254/16）、多播与广播（IPv6 放行链路本地与多播），其余流量全部拦截。**网卡的网关/IP/DNS 配置完全不动**，开关瞬时生效、不重启网卡；过滤规则是进程级临时规则，关闭或退出程序即自动撤销，不会残留
- **恢复自动获取(DHCP)**：若某张网卡之前被改成过静态配置，可用该按钮清空静态设置并重新获取租约
- **退出程序**：仅通过托盘图标的右键菜单"退出"
