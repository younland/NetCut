; NetCut 安装包构建脚本
; 用法: ISCC.exe installer\netcut.iss （需先 cargo build --release，或直接运行 package.bat）

#define MyAppName "NetCut"
#define MyAppVersion "0.1.0"
#define MyAppExeName "netcut.exe"

[Setup]
AppId={{7B2E9C41-3A5F-4E8D-9C1B-2F4A6D8E0B3C}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher="NetCut"
DefaultDirName={autopf64}\NetCut
DefaultGroupName={#MyAppName}
DisableProgramGroupPage=yes
; 应用需要管理员权限操作网卡，安装器同样要求管理员
PrivilegesRequired=admin
WizardStyle=modern
Compression=lzma2
SolidCompression=yes
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
OutputDir=..\dist
OutputBaseFilename=NetCut-{#MyAppVersion}-setup
SetupIconFile=..\icon.ico
UninstallDisplayIcon={app}\{#MyAppExeName}
UninstallDisplayName={#MyAppName}

[Languages]
Name: "chinesesimp"; MessagesFile: "ChineseSimplified.isl"

[Tasks]
Name: "desktopicon"; Description: "创建桌面快捷方式"; GroupDescription: "附加图标："; Flags: unchecked
Name: "startup"; Description: "开机自动启动 NetCut（计划任务，免 UAC 弹窗）"; GroupDescription: "其他选项："; Flags: checkedonce

[Files]
Source: "..\target\release\netcut.exe"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[Run]
; 开机自启使用计划任务（ONLOGON + 最高权限），登录时不弹 UAC
Filename: "schtasks.exe"; Parameters: "/Create /F /TN ""{#MyAppName}"" /SC ONLOGON /RL HIGHEST /TR ""\""{app}\{#MyAppExeName}\"""""; Tasks: startup; Flags: runhidden
Filename: "{app}\{#MyAppExeName}"; Description: "启动 {#MyAppName}"; Flags: nowait postinstall skipifsilent

[UninstallRun]
Filename: "schtasks.exe"; Parameters: "/Delete /F /TN ""{#MyAppName}"""; RunOnceId: "DelNetCutTask"; Flags: runhidden

[UninstallDelete]
Type: filesandordirs; Name: "{app}"
