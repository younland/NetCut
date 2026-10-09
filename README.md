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
- **局域网模式**：底部按钮一键对所有网卡生效（显示"已关闭/已开启"）——清空各网卡默认网关（保留各自 IP，DHCP 分配或自定义静态都一样），只能访问局域网；再次点击按备份精确恢复原配置（DHCP 网卡恢复为 DHCP）。备份位于 `%APPDATA%\NetCut\lan-backup.json`
- **退出程序**：仅通过托盘图标的右键菜单"退出"
