#![cfg_attr(target_os = "windows", windows_subsystem = "windows")]

use futures::{StreamExt, channel::mpsc::UnboundedSender};
use gpui_kit::base::StyledExt as _;
use gpui_kit::component::{
    ActiveTheme, Disableable, Icon, IconName, Sizable,
    button::{Button, ButtonVariants},
    combobox::{Combobox, ComboboxState},
    searchable_list::{SearchableGroup, SearchableListItem, SearchableVec},
    theme::{Theme, ThemeMode},
};
use gpui_kit::*;
use tray_icon::{MouseButton, MouseButtonState, TrayIcon, TrayIconBuilder, TrayIconEvent};
use windows_sys::Win32::Devices::DeviceAndDriverInstallation as setup;
use windows_sys::Win32::Foundation::GetLastError;

// ---------------------------------------------------------------------------
// 状态
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum NetStatus {
    Unknown,
    Connected,
    Disconnected,
}

#[derive(Clone)]
struct AdapterInfo {
    devinst: u32,
    guid: String,
    /// 友好名称："WLAN"、"以太网"
    name: String,
    /// 原始描述："802.11n USB Wireless LAN Card"
    desc: String,
    /// "Up" | "Disconnected" | "Disabled"
    state: &'static str,
    /// 当前 IP（如 192.168.1.5）
    ip: String,
    /// 子网掩码（如 255.255.255.0）
    mask: String,
    /// 默认网关
    gateway: String,
    /// DNS 服务器（多个用逗号分隔）
    dns: String,
}

enum Msg {
    Toggle,
    SetAdapter {
        devinst: u32,
        enable: bool,
    },
    LanApply {
        enable: bool,
    },
    RestoreDhcp {
        devinst: u32,
        guid: String,
    },
    /// 定时刷新：后台重新读取网卡与地址信息
    Refresh,
    RefreshResult(Result<(NetStatus, Vec<AdapterInfo>), String>),
    ShowWindow,
    Quit,
    NetResult(Result<(NetStatus, Vec<AdapterInfo>), String>),
    LanResult(Result<(NetStatus, Vec<AdapterInfo>), String>, bool),
}

struct NetCut {
    tx: UnboundedSender<Msg>,
    tray: Option<TrayIcon>,
    /// 上次应用的托盘图标色调（None = 原色），用于避免重复设置导致的闪烁
    tray_lan_on: Option<bool>,
    tray_tooltip: String,
    status: NetStatus,
    busy: bool,
    /// 当前处于局域网模式的网卡 GUID
    lan_adapters: std::collections::HashSet<String>,
    /// 下拉框中选中的网卡 GUID
    selected: Option<String>,
    adapters: Vec<AdapterInfo>,
    error: Option<String>,
    window: Option<AnyWindowHandle>,
}

impl Global for NetCut {}

// ---------------------------------------------------------------------------
// 网络控制（SetupAPI / cfgmgr32，纯 Rust，等价于设备管理器启用/禁用网卡）
// ---------------------------------------------------------------------------

/// 设备类：网络适配器（4D36E972-E325-11CE-BFC1-08002BE10318）
const GUID_DEVCLASS_NET: windows_sys::core::GUID =
    windows_sys::core::GUID::from_u128(0x4D36E972_E325_11CE_BFC1_08002BE10318);

const ERROR_SUCCESS_REBOOT_REQUIRED: u32 = 3010;

fn open_net_devices() -> Result<setup::HDEVINFO, String> {
    let hdi = unsafe {
        setup::SetupDiGetClassDevsW(
            &GUID_DEVCLASS_NET,
            std::ptr::null(),
            std::ptr::null_mut(),
            setup::DIGCF_PRESENT,
        )
    };
    if hdi as isize == -1 {
        Err(format!(
            "SetupDiGetClassDevsW 失败 (Win32 错误 {})",
            unsafe { GetLastError() }
        ))
    } else {
        Ok(hdi)
    }
}

fn new_devinfo_data() -> setup::SP_DEVINFO_DATA {
    let mut dev: setup::SP_DEVINFO_DATA = unsafe { std::mem::zeroed() };
    dev.cbSize = std::mem::size_of::<setup::SP_DEVINFO_DATA>() as u32;
    dev
}

/// 返回 (是否启用, 是否已启动连接)。已禁用 => (false, false)。
fn devnode_state(devinst: u32) -> (bool, bool) {
    let mut status = 0u32;
    let mut problem = 0u32;
    let cr = unsafe { setup::CM_Get_DevNode_Status(&mut status, &mut problem, devinst, 0) };
    if cr != setup::CR_SUCCESS {
        return (true, false);
    }
    let enabled = problem != setup::CM_PROB_DISABLED;
    let started = status & setup::DN_STARTED != 0;
    (enabled, started)
}

/// 过滤系统伪接口，仅保留用户可见的真实网络设备
///（与"网络连接"面板 / Get-NetAdapter 默认显示一致：
/// 隐藏 WAN Miniport、内核调试网卡、Wi-Fi Direct/热点虚拟适配器）。
fn is_physical_adapter(hdi: setup::HDEVINFO, dev: &setup::SP_DEVINFO_DATA) -> bool {
    let mut buf = [0u16; 512];
    let ok = unsafe {
        setup::SetupDiGetDeviceInstanceIdW(
            hdi,
            dev,
            buf.as_mut_ptr(),
            buf.len() as u32,
            std::ptr::null_mut(),
        )
    };
    if ok == 0 {
        return false;
    }
    let len = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    let id = String::from_utf16_lossy(&buf[..len]).to_uppercase();
    !(id.starts_with("SWD\\") || id.starts_with("ROOT\\KDNIC") || id.contains("\\VWIFIMP_"))
}

fn read_device_property(hdi: setup::HDEVINFO, dev: &setup::SP_DEVINFO_DATA, property: u32) -> String {
    let mut buf = [0u16; 256];
    let ok = unsafe {
        setup::SetupDiGetDeviceRegistryPropertyW(
            hdi,
            dev,
            property,
            std::ptr::null_mut(),
            buf.as_mut_ptr() as *mut u8,
            (buf.len() * 2) as u32,
            std::ptr::null_mut(),
        )
    };
    if ok == 0 {
        return String::new();
    }
    let len = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    String::from_utf16_lossy(&buf[..len])
}

/// 友好名称（"WLAN"、"以太网"），取不到时用原始描述。
fn device_name(hdi: setup::HDEVINFO, dev: &setup::SP_DEVINFO_DATA) -> String {
    let name = read_device_property(hdi, dev, setup::SPDRP_FRIENDLYNAME);
    if name.is_empty() {
        device_desc(hdi, dev)
    } else {
        name
    }
}

/// 原始适配器描述（"802.11n USB Wireless LAN Card"）。
fn device_desc(hdi: setup::HDEVINFO, dev: &setup::SP_DEVINFO_DATA) -> String {
    read_device_property(hdi, dev, 0) // SPDRP_DEVICEDESC
}

fn query_status() -> Result<(NetStatus, Vec<AdapterInfo>), String> {
    let hdi = open_net_devices()?;
    let addrs = adapter_addresses();
    let mut adapters = Vec::new();
    let mut index = 0u32;
    loop {
        let mut dev = new_devinfo_data();
        if unsafe { setup::SetupDiEnumDeviceInfo(hdi, index, &mut dev) } == 0 {
            break;
        }
        index += 1;
        if !is_physical_adapter(hdi, &dev) {
            continue;
        }
        let desc = device_desc(hdi, &dev);
        // 用设备描述匹配 IP Helper 的接口信息，取其连接名（"WLAN"/"以太网"）与接口 GUID
        let runtime = addrs
            .iter()
            .find(|a| a.desc.eq_ignore_ascii_case(&desc))
            .or_else(|| {
                let fallback = device_name(hdi, &dev);
                addrs
                    .iter()
                    .find(|a| a.name.eq_ignore_ascii_case(&fallback))
            });
        let name = runtime
            .map(|a| a.name.clone())
            .filter(|n| !n.is_empty())
            .unwrap_or_else(|| device_name(hdi, &dev));
        let guid = runtime.map(|a| a.guid.clone()).unwrap_or_default();

        let (enabled, started) = devnode_state(dev.DevInst);
        let state = if !enabled {
            "Disabled"
        } else if started {
            "Up"
        } else {
            "Disconnected"
        };

        // 运行时地址（DHCP 或静态都已生效），注册表值作兜底
        let mut ip = String::new();
        let mut mask = String::new();
        if let Some((addr, prefix)) = runtime.and_then(|a| a.ip) {
            ip = addr.to_string();
            mask = prefix_to_mask(prefix);
        }
        let mut dns = runtime
            .map(|a| {
                a.dns
                    .iter()
                    .map(|d| d.to_string())
                    .collect::<Vec<_>>()
                    .join(",")
            })
            .unwrap_or_default();
        let mut gateway = String::new();
        if !guid.is_empty() {
            if let Ok(key) = iface_reg::open(&guid) {
                if ip.is_empty() {
                    ip = iface_reg::read_multi_sz(key, "IPAddress")
                        .into_iter()
                        .next()
                        .unwrap_or_default();
                    mask = iface_reg::read_multi_sz(key, "SubnetMask")
                        .into_iter()
                        .next()
                        .unwrap_or_default();
                }
                gateway = iface_reg::read_multi_sz(key, "DefaultGateway")
                    .into_iter()
                    .next()
                    .unwrap_or_default();
                if gateway.is_empty() {
                    gateway = iface_reg::read_multi_sz(key, "DhcpDefaultGateway")
                        .into_iter()
                        .next()
                        .unwrap_or_default();
                }
                if dns.is_empty() {
                    dns = iface_reg::read_string(key, "NameServer");
                }
                if dns.is_empty() {
                    dns = iface_reg::read_string(key, "DhcpNameServer");
                }
                iface_reg::close(key);
            }
        }

        adapters.push(AdapterInfo {
            devinst: dev.DevInst,
            guid,
            name,
            desc,
            state,
            ip,
            mask,
            gateway,
            dns,
        });
    }
    unsafe { setup::SetupDiDestroyDeviceInfoList(hdi) };

    if adapters.is_empty() {
        return Err("未找到物理网络适配器".to_string());
    }
    let status = if adapters.iter().any(|a| a.state == "Up") {
        NetStatus::Connected
    } else {
        NetStatus::Disconnected
    };
    Ok((status, adapters))
}

/// 对单个设备执行启用/禁用，等价于设备管理器中的操作。
fn apply_state_change(
    hdi: setup::HDEVINFO,
    dev: &setup::SP_DEVINFO_DATA,
    enabled: bool,
) -> Result<(), String> {
    let mut params: setup::SP_PROPCHANGE_PARAMS = unsafe { std::mem::zeroed() };
    params.ClassInstallHeader.cbSize = std::mem::size_of::<setup::SP_CLASSINSTALL_HEADER>() as u32;
    params.ClassInstallHeader.InstallFunction = setup::DIF_PROPERTYCHANGE;
    params.StateChange = if enabled {
        setup::DICS_ENABLE
    } else {
        setup::DICS_DISABLE
    };
    params.Scope = setup::DICS_FLAG_GLOBAL;
    params.HwProfile = 0;

    let set_ok = unsafe {
        setup::SetupDiSetClassInstallParamsW(
            hdi,
            dev,
            &params as *const _ as *const setup::SP_CLASSINSTALL_HEADER,
            std::mem::size_of::<setup::SP_PROPCHANGE_PARAMS>() as u32,
        )
    };
    if set_ok == 0 {
        return Err(format!(
            "{} (设置参数失败 {})",
            device_name(hdi, dev),
            unsafe { GetLastError() }
        ));
    }

    let call_ok = unsafe { setup::SetupDiCallClassInstaller(setup::DIF_PROPERTYCHANGE, hdi, dev) };
    if call_ok == 0 {
        let err = unsafe { GetLastError() };
        if err != ERROR_SUCCESS_REBOOT_REQUIRED {
            return Err(format!("{} (错误 {})", device_name(hdi, dev), err));
        }
    }
    Ok(())
}

/// 对指定 DevInst 的网卡执行一次启用/禁用。
/// 每次调用都重新打开设备集合：禁用后旧的 SP_DEVINFO_DATA/句柄会失效。
fn set_device_state(devinst: u32, enabled: bool) -> Result<(), String> {
    let hdi = open_net_devices()?;
    let mut index = 0u32;
    let mut result = Err(format!("未找到目标适配器 (DevInst {devinst})"));
    loop {
        let mut dev = new_devinfo_data();
        if unsafe { setup::SetupDiEnumDeviceInfo(hdi, index, &mut dev) } == 0 {
            break;
        }
        index += 1;
        if dev.DevInst != devinst {
            continue;
        }
        result = apply_state_change(hdi, &dev, enabled);
        break;
    }
    unsafe { setup::SetupDiDestroyDeviceInfoList(hdi) };
    result
}

/// 在独立线程执行可能长时间阻塞的 Win32 调用，超时则放弃等待
/// （调用本身无法中断，但界面不会因此卡死）。
fn with_timeout<T: Send + 'static>(
    timeout: std::time::Duration,
    work: impl FnOnce() -> T + Send + 'static,
) -> Option<T> {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(work());
    });
    rx.recv_timeout(timeout).ok()
}

/// 启用或禁用所有物理网络适配器（单卡超时 8 秒，避免个别设备拖死整体）。
fn set_network(enabled: bool) -> Result<(), String> {
    let (_, adapters) = query_status()?;
    let mut changed = 0u32;
    let mut failed = Vec::new();

    for adapter in adapters {
        let is_enabled = adapter.state != "Disabled";
        if is_enabled == enabled {
            continue; // 已处于目标状态
        }
        let devinst = adapter.devinst;
        let name = adapter.name.clone();
        match with_timeout(std::time::Duration::from_secs(8), move || {
            set_device_state(devinst, enabled)
        }) {
            Some(Ok(())) => changed += 1,
            Some(Err(err)) => failed.push(err),
            None => failed.push(format!("{name} 操作超时")),
        }
    }

    if changed == 0 && !failed.is_empty() {
        Err(format!("适配器操作失败: {}", failed.join("; ")))
    } else {
        Ok(())
    }
}

/// 启用或禁用指定的一个物理网络适配器。
fn set_adapter(devinst: u32, enabled: bool) -> Result<(), String> {
    match with_timeout(std::time::Duration::from_secs(8), move || {
        set_device_state(devinst, enabled)
    }) {
        Some(result) => result,
        None => Err("操作超时（设备未响应）".to_string()),
    }
}

/// 统一的后台操作包装：捕获 panic 并始终回传结果，避免 busy 永久卡住。
/// 同时把结果写入 %TEMP%\netcut-ops.log，便于排查"点了没反应"的问题。
fn run_operation<F>(
    tx: UnboundedSender<Msg>,
    label: &'static str,
    work: F,
    wrap: impl FnOnce(NetResult) -> Msg + Send + 'static,
) where
    F: FnOnce() -> NetResult + Send + 'static + std::panic::UnwindSafe,
{
    std::thread::spawn(move || {
        let started = std::time::Instant::now();
        let result = std::panic::catch_unwind(work)
            .unwrap_or_else(|_| Err("内部错误（详见 %TEMP%\\netcut-panic.log）".to_string()));
        let elapsed = started.elapsed();
        log_operation(label, &result, elapsed);
        let _ = tx.unbounded_send(wrap(result));
    });
}

/// 追加一条操作日志（时间 / 操作 / 耗时 / 结果）
fn log_operation(label: &str, result: &NetResult, elapsed: std::time::Duration) {
    let summary = match result {
        Ok((status, adapters)) => format!(
            "OK status={:?} adapters={}",
            status,
            adapters.len()
        ),
        Err(err) => format!("ERR {err}"),
    };
    let line = format!(
        "[{:?}] {label} ({:.2}s) {summary}\n",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
        elapsed.as_secs_f64()
    );
    let path = std::env::temp_dir().join("netcut-ops.log");
    let _ = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .and_then(|mut f| std::io::Write::write_all(&mut f, line.as_bytes()));
}

fn spawn_net_thread(tx: UnboundedSender<Msg>, enable: Option<bool>) {
    let label = match enable {
        Some(true) => "一键联网",
        Some(false) => "一键断网",
        None => "查询状态",
    };
    run_operation(
        tx,
        label,
        move || match enable {
            Some(enable) => set_network(enable).and_then(|_| query_status()),
            None => query_status(),
        },
        Msg::NetResult,
    );
}

fn spawn_adapter_thread(tx: UnboundedSender<Msg>, devinst: u32, enable: bool) {
    run_operation(
        tx,
        if enable { "单卡恢复" } else { "单卡断开" },
        move || set_adapter(devinst, enable).and_then(|_| query_status()),
        Msg::NetResult,
    );
}

type NetResult = Result<(NetStatus, Vec<AdapterInfo>), String>;

// ---------------------------------------------------------------------------
// 局域网模式（按网卡清空默认网关，禁止外网；退出时补回网关）
// ---------------------------------------------------------------------------

#[derive(serde::Serialize, serde::Deserialize, Clone, Default)]
struct AdapterBackup {
    devinst: u32,
    /// 接口索引（恢复路由时使用；DHCP 网卡的网关只在运行时路由表里）
    #[serde(default)]
    if_index: u32,
    guid: String,
    name: String,
    enable_dhcp: bool,
    ip: Vec<String>,
    mask: Vec<String>,
    gateway: Vec<String>,
    /// DHCP 下发的网关（用于退出局域网模式时恢复路由）
    #[serde(default)]
    dhcp_gateway: Vec<String>,
    /// 启用局域网模式时该网卡实际生效的默认网关（取自路由表，最可靠）
    #[serde(default)]
    runtime_gateway: Option<String>,
    dns: String,
}

#[derive(serde::Serialize, serde::Deserialize, Default)]
struct LanBackup {
    adapters: Vec<AdapterBackup>,
    persistent_routes: Vec<String>,
}

fn app_data_dir() -> std::path::PathBuf {
    match std::env::var_os("APPDATA") {
        Some(dir) => std::path::PathBuf::from(dir).join("NetCut"),
        None => std::env::temp_dir().join("NetCut"),
    }
}

fn lan_backup_path() -> std::path::PathBuf {
    app_data_dir().join("lan-backup.json")
}

fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn prefix_to_mask(prefix: u8) -> String {
    let bits = u32::MAX << (32 - prefix.clamp(0, 32));
    format!(
        "{}.{}.{}.{}",
        bits >> 24,
        (bits >> 16) & 0xff,
        (bits >> 8) & 0xff,
        bits & 0xff
    )
}

#[derive(Clone)]
struct AdapterAddrs {
    /// 接口 GUID（与 AdapterName 一致，形如 {GUID}）
    guid: String,
    /// 接口索引（路由表用）
    if_index: u32,
    /// 连接名（"WLAN"、"以太网"）
    name: String,
    /// 设备描述（"Realtek PCIe GbE Family Controller"）
    desc: String,
    ip: Option<(std::net::Ipv4Addr, u8)>,
    dns: Vec<std::net::Ipv4Addr>,
}

unsafe fn sockaddr_ipv4(
    addr: *mut windows_sys::Win32::Networking::WinSock::SOCKADDR,
) -> Option<std::net::Ipv4Addr> {
    if addr.is_null() {
        return None;
    }
    if unsafe { (*addr).sa_family } != windows_sys::Win32::Networking::WinSock::AF_INET {
        return None;
    }
    let sin = addr as *const windows_sys::Win32::Networking::WinSock::SOCKADDR_IN;
    let bytes = unsafe { (*sin).sin_addr.S_un.S_addr }.to_ne_bytes();
    Some(std::net::Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]))
}

fn if_index_of(guid: &str) -> Option<u32> {
    adapter_addresses()
        .into_iter()
        .find(|a| a.guid.eq_ignore_ascii_case(guid))
        .map(|a| a.if_index)
}

/// 从路由表读取指定网卡当前生效的默认网关。
fn current_default_gateway(if_index: u32) -> Option<std::net::Ipv4Addr> {
    use windows_sys::Win32::NetworkManagement::IpHelper as iphlp;

    let mut size = 0u32;
    unsafe {
        iphlp::GetIpForwardTable(std::ptr::null_mut(), &mut size, 0);
    }
    if size == 0 {
        return None;
    }
    let mut buf = vec![0u8; size as usize];
    let table = buf.as_mut_ptr() as *mut iphlp::MIB_IPFORWARDTABLE;
    let ret = unsafe { iphlp::GetIpForwardTable(table, &mut size, 0) };
    if ret != 0 {
        return None;
    }
    let count = unsafe { (*table).dwNumEntries } as usize;
    let rows = unsafe { std::slice::from_raw_parts((*table).table.as_ptr(), count) };
    for row in rows {
        if row.dwForwardDest == 0 && row.dwForwardMask == 0 && row.dwForwardIfIndex == if_index {
            if row.dwForwardNextHop == 0 {
                continue;
            }
            let octets = row.dwForwardNextHop.to_ne_bytes();
            return Some(std::net::Ipv4Addr::new(
                octets[0], octets[1], octets[2], octets[3],
            ));
        }
    }
    None
}

/// 删除指定网卡的运行时默认路由（0.0.0.0/0），立即生效且无需重启网卡。
fn delete_default_routes(if_index: u32) -> Result<(), String> {
    use windows_sys::Win32::NetworkManagement::IpHelper as iphlp;

    let mut size = 0u32;
    unsafe {
        iphlp::GetIpForwardTable(std::ptr::null_mut(), &mut size, 0);
    }
    if size == 0 {
        return Ok(());
    }
    let mut buf = vec![0u8; size as usize];
    let table = buf.as_mut_ptr() as *mut iphlp::MIB_IPFORWARDTABLE;
    let ret = unsafe { iphlp::GetIpForwardTable(table, &mut size, 0) };
    if ret != 0 {
        return Err(format!("读取路由表失败（错误 {ret}）"));
    }

    let count = unsafe { (*table).dwNumEntries } as usize;
    let rows = unsafe { std::slice::from_raw_parts((*table).table.as_ptr(), count) };
    for row in rows {
        if row.dwForwardDest == 0 && row.dwForwardMask == 0 && row.dwForwardIfIndex == if_index {
            unsafe {
                iphlp::DeleteIpForwardEntry(row);
            }
        }
    }
    Ok(())
}

/// 恢复指定网卡的默认路由（网关），立即生效。
fn add_default_route(if_index: u32, gateway: std::net::Ipv4Addr) -> Result<(), String> {
    use windows_sys::Win32::NetworkManagement::IpHelper as iphlp;

    let mut row: iphlp::MIB_IPFORWARDROW = unsafe { std::mem::zeroed() };
    row.dwForwardDest = 0;
    row.dwForwardMask = 0;
    row.dwForwardNextHop = u32::from_ne_bytes(gateway.octets());
    row.dwForwardIfIndex = if_index;
    row.Anonymous1.dwForwardType = iphlp::MIB_IPROUTE_TYPE_INDIRECT as u32;
    row.Anonymous2.dwForwardProto = 3; // MIB_IPPROTO_NETMGMT
    row.dwForwardMetric1 = 1;

    let ret = unsafe { iphlp::CreateIpForwardEntry(&row) };
    if ret != 0 {
        return Err(format!("恢复默认路由失败（错误 {ret}）"));
    }
    Ok(())
}

/// 读取网卡的运行时信息（连接名/设备描述/当前 IP/前缀/DNS），
/// DHCP 分配与自定义静态都能取到。
fn adapter_addresses() -> Vec<AdapterAddrs> {
    use windows_sys::Win32::NetworkManagement::IpHelper as iphlp;

    let flags = iphlp::GAA_FLAG_SKIP_ANYCAST | iphlp::GAA_FLAG_SKIP_MULTICAST;
    let mut size = 0u32;
    unsafe {
        iphlp::GetAdaptersAddresses(0, flags, std::ptr::null(), std::ptr::null_mut(), &mut size);
    }
    if size == 0 {
        return Vec::new();
    }
    let mut buf = vec![0u8; size as usize];
    let ret = unsafe {
        iphlp::GetAdaptersAddresses(
            0,
            flags,
            std::ptr::null(),
            buf.as_mut_ptr() as *mut iphlp::IP_ADAPTER_ADDRESSES_LH,
            &mut size,
        )
    };
    if ret != 0 {
        return Vec::new();
    }

    let mut out = Vec::new();
    let mut cur = buf.as_mut_ptr() as *mut iphlp::IP_ADAPTER_ADDRESSES_LH;
    while !cur.is_null() {
        let a = unsafe { &*cur };
        let guid = unsafe { std::ffi::CStr::from_ptr(a.AdapterName as *const i8) }
            .to_string_lossy()
            .into_owned();

        let mut ip = None;
        let mut unicast = a.FirstUnicastAddress;
        while !unicast.is_null() {
            let u = unsafe { &*unicast };
            if let Some(addr) = unsafe { sockaddr_ipv4(u.Address.lpSockaddr) } {
                ip = Some((addr, u.OnLinkPrefixLength));
                break;
            }
            unicast = u.Next;
        }

        let mut dns = Vec::new();
        let mut dns_cur = a.FirstDnsServerAddress;
        while !dns_cur.is_null() {
            let d = unsafe { &*dns_cur };
            if let Some(addr) = unsafe { sockaddr_ipv4(d.Address.lpSockaddr) } {
                dns.push(addr);
            }
            dns_cur = d.Next;
        }

        out.push(AdapterAddrs {
            guid,
            if_index: unsafe { a.Anonymous1.Anonymous.IfIndex },
            name: if a.FriendlyName.is_null() {
                String::new()
            } else {
                let len = (0..)
                    .take_while(|&i| unsafe { *a.FriendlyName.add(i) } != 0)
                    .count();
                String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(a.FriendlyName, len) })
            },
            desc: if a.Description.is_null() {
                String::new()
            } else {
                let len = (0..)
                    .take_while(|&i| unsafe { *a.Description.add(i) } != 0)
                    .count();
                String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(a.Description, len) })
            },
            ip,
            dns,
        });
        cur = a.Next;
    }
    out
}

mod iface_reg {
    use super::*;
    use windows_sys::Win32::System::Registry as reg;

    pub fn open(guid: &str) -> Result<reg::HKEY, String> {
        let path =
            format!("SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\{guid}");
        let mut key: reg::HKEY = std::ptr::null_mut();
        let err = unsafe {
            reg::RegOpenKeyExW(
                reg::HKEY_LOCAL_MACHINE,
                to_wide(&path).as_ptr(),
                0,
                reg::KEY_READ | reg::KEY_WRITE,
                &mut key,
            )
        };
        if err != 0 {
            Err(format!("打开注册表项失败（{guid}），错误 {err}"))
        } else {
            Ok(key)
        }
    }

    pub unsafe fn query(key: reg::HKEY, name: &str, buf: &mut Vec<u8>) -> Option<(u32, u32)> {        let mut ty = 0u32;
        let mut len = buf.len() as u32;
        let err = unsafe {
            reg::RegQueryValueExW(
                key,
                to_wide(name).as_ptr(),
                std::ptr::null(),
                &mut ty,
                buf.as_mut_ptr(),
                &mut len,
            )
        };
        if err == 0 { Some((ty, len)) } else { None }
    }

    pub fn read_multi_sz(key: reg::HKEY, name: &str) -> Vec<String> {
        unsafe {
            let mut buf = vec![0u8; 4096];
            let Some((ty, len)) = query(key, name, &mut buf) else {
                return Vec::new();
            };
            let units = std::slice::from_raw_parts(buf.as_ptr() as *const u16, len as usize / 2);
            let joined: Vec<u16> = if ty == reg::REG_SZ {
                let end = units.iter().position(|&c| c == 0).unwrap_or(units.len());
                units[..end].to_vec()
            } else {
                // REG_MULTI_SZ: 以双 \0 结束
                let end = units
                    .windows(2)
                    .position(|w| w == [0, 0])
                    .map(|i| i + 1)
                    .unwrap_or(units.len());
                units[..end].to_vec()
            };
            joined
                .split(|&c| c == 0)
                .filter(|s| !s.is_empty())
                .map(|s| String::from_utf16_lossy(s))
                .collect()
        }
    }

    pub fn read_string(key: reg::HKEY, name: &str) -> String {
        unsafe {
            let mut buf = vec![0u8; 4096];
            let Some((_, len)) = query(key, name, &mut buf) else {
                return String::new();
            };
            let units = std::slice::from_raw_parts(buf.as_ptr() as *const u16, len as usize / 2);
            let end = units.iter().position(|&c| c == 0).unwrap_or(units.len());
            String::from_utf16_lossy(&units[..end])
        }
    }

    pub fn read_dword(key: reg::HKEY, name: &str) -> Option<u32> {
        unsafe {
            let mut buf = vec![0u8; 8];
            let (ty, len) = query(key, name, &mut buf)?;
            if ty == reg::REG_DWORD && len == 4 {
                Some(u32::from_ne_bytes(buf[..4].try_into().ok()?))
            } else {
                None
            }
        }
    }

    pub fn write_multi_sz(key: reg::HKEY, name: &str, values: &[String]) {
        let mut data: Vec<u16> = values.iter().flat_map(|v| to_wide(v)).collect();
        data.push(0);
        unsafe {
            reg::RegSetValueExW(
                key,
                to_wide(name).as_ptr(),
                0,
                reg::REG_MULTI_SZ,
                data.as_ptr() as *const u8,
                (data.len() * 2) as u32,
            );
        }
    }

    pub fn write_string(key: reg::HKEY, name: &str, value: &str) {
        let data = to_wide(value);
        unsafe {
            reg::RegSetValueExW(
                key,
                to_wide(name).as_ptr(),
                0,
                reg::REG_SZ,
                data.as_ptr() as *const u8,
                (data.len() * 2) as u32,
            );
        }
    }

    pub fn write_dword(key: reg::HKEY, name: &str, value: u32) {
        unsafe {
            reg::RegSetValueExW(
                key,
                to_wide(name).as_ptr(),
                0,
                reg::REG_DWORD,
                &value as *const u32 as *const u8,
                4,
            );
        }
    }

    pub fn delete(key: reg::HKEY, name: &str) {
        unsafe {
            reg::RegDeleteValueW(key, to_wide(name).as_ptr());
        }
    }

    pub fn close(key: reg::HKEY) {
        unsafe {
            reg::RegCloseKey(key);
        }
    }
}

fn read_persistent_routes() -> Vec<String> {
    use windows_sys::Win32::System::Registry as reg;
    let mut key: reg::HKEY = std::ptr::null_mut();
    let err = unsafe {
        reg::RegOpenKeyExW(
            reg::HKEY_LOCAL_MACHINE,
            to_wide("SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters").as_ptr(),
            0,
            reg::KEY_READ | reg::KEY_WRITE,
            &mut key,
        )
    };
    if err != 0 {
        return Vec::new();
    }
    let routes = iface_reg::read_multi_sz(key, "PersistentRoutes");
    iface_reg::close(key);
    routes
}

fn write_persistent_routes(routes: &[String]) {
    use windows_sys::Win32::System::Registry as reg;
    let mut key: reg::HKEY = std::ptr::null_mut();
    let err = unsafe {
        reg::RegOpenKeyExW(
            reg::HKEY_LOCAL_MACHINE,
            to_wide("SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters").as_ptr(),
            0,
            reg::KEY_READ | reg::KEY_WRITE,
            &mut key,
        )
    };
    if err != 0 {
        return;
    }
    iface_reg::write_multi_sz(key, "PersistentRoutes", routes);
    iface_reg::close(key);
}

fn load_backup() -> Option<LanBackup> {
    let text = std::fs::read_to_string(lan_backup_path()).ok()?;
    serde_json::from_str(&text).ok()
}

fn save_backup(backup: &LanBackup) -> Result<(), String> {
    let _ = std::fs::create_dir_all(app_data_dir());
    std::fs::write(
        lan_backup_path(),
        serde_json::to_string_pretty(backup).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())
}

/// 当前处于局域网模式的网卡 GUID 集合（由备份文件恢复，程序重启后仍能识别）。
fn lan_mode_guids() -> std::collections::HashSet<String> {
    load_backup()
        .map(|b| b.adapters.into_iter().map(|a| a.guid).collect())
        .unwrap_or_default()
}

/// 对单个网卡启用局域网模式：保留它当前的 IP（自定义静态或 DHCP 分配的都保留），
/// 只把默认网关置空 —— 没有默认路由即无法访问外网，仅局域网可达。
/// 首次启用时备份原配置，退出时精确恢复（DHCP 网卡恢复为 DHCP）。
fn apply_lan_adapter(guid: &str, name: &str, devinst: u32) -> Result<(), String> {
    let mut backup = load_backup().unwrap_or_else(|| LanBackup {
        adapters: Vec::new(),
        persistent_routes: read_persistent_routes(),
    });

    let key = iface_reg::open(guid)?;
    let if_index = if_index_of(guid).unwrap_or(0);
    // 已备份过则保留最初的原始配置，避免二次覆盖
    if !backup.adapters.iter().any(|a| a.guid == guid) {
        backup.adapters.push(AdapterBackup {
            devinst,
            if_index,
            guid: guid.to_string(),
            name: name.to_string(),
            enable_dhcp: iface_reg::read_dword(key, "EnableDHCP").unwrap_or(1) == 1,
            ip: iface_reg::read_multi_sz(key, "IPAddress"),
            mask: iface_reg::read_multi_sz(key, "SubnetMask"),
            gateway: iface_reg::read_multi_sz(key, "DefaultGateway"),
            dhcp_gateway: iface_reg::read_multi_sz(key, "DhcpDefaultGateway"),
            // 路由表里的网关最可靠（DHCP 网卡的注册表项常为空）
            runtime_gateway: if if_index != 0 {
                current_default_gateway(if_index).map(|g| g.to_string())
            } else {
                None
            },
            dns: iface_reg::read_string(key, "NameServer"),
        });
    }
    let original = backup
        .adapters
        .iter()
        .find(|a| a.guid == guid)
        .cloned()
        .unwrap_or_default();

    // 保留当前生效的 IP/掩码/DNS（DHCP 租约或自定义静态），仅去掉网关
    let current = adapter_addresses()
        .into_iter()
        .find(|a| a.guid.eq_ignore_ascii_case(guid));

    let runtime = current.as_ref().and_then(|a| a.ip);
    let (ip, mask) = match runtime {
        Some((ip, prefix)) => (ip.to_string(), prefix_to_mask(prefix)),
        None => match (original.ip.first(), original.mask.first()) {
            (Some(ip), Some(mask)) => (ip.clone(), mask.clone()),
            _ => {
                iface_reg::close(key);
                return Err(format!(
                    "{name} 当前没有可用的 IPv4 地址，无法启用局域网模式"
                ));
            }
        },
    };
    let dns = match current.as_ref() {
        Some(a) if !a.dns.is_empty() => a
            .dns
            .iter()
            .map(|d| d.to_string())
            .collect::<Vec<_>>()
            .join(","),
        _ => original.dns.clone(),
    };

    iface_reg::write_dword(key, "EnableDHCP", 0);
    iface_reg::write_multi_sz(key, "IPAddress", &[ip]);
    iface_reg::write_multi_sz(key, "SubnetMask", &[mask]);
    iface_reg::write_multi_sz(key, "DefaultGateway", &[]); // 清空网关 = 禁止外网
    iface_reg::write_string(key, "NameServer", dns.trim());
    iface_reg::close(key);

    // 先落盘备份，再删掉运行时默认路由（立即生效，不重启网卡）
    save_backup(&backup)?;
    if if_index != 0 {
        delete_default_routes(if_index)?;
    }
    Ok(())
}

/// 对单个网卡退出局域网模式：按备份恢复该网卡原配置。
fn restore_lan_adapter(guid: &str) -> Result<(), String> {
    let Some(mut backup) = load_backup() else {
        return Ok(()); // 没有备份，无需恢复
    };
    let Some(index) = backup.adapters.iter().position(|a| a.guid == guid) else {
        return Ok(());
    };
    let ab = backup.adapters.remove(index);

    // 退出局域网模式 = 保留当前的静态 IP/掩码/DNS，只把默认网关写回去
    let gateway = ab
        .runtime_gateway
        .as_deref()
        .and_then(|g| g.trim().parse::<std::net::Ipv4Addr>().ok())
        .or_else(|| {
            ab.gateway
                .first()
                .and_then(|g| g.trim().parse::<std::net::Ipv4Addr>().ok())
        })
        .or_else(|| {
            ab.dhcp_gateway
                .first()
                .and_then(|g| g.trim().parse::<std::net::Ipv4Addr>().ok())
        });

    let key = iface_reg::open(&ab.guid)?;
    match gateway {
        Some(gateway) => {
            // 保留静态 IP/掩码/DNS，只补回默认网关
            iface_reg::write_multi_sz(key, "DefaultGateway", &[gateway.to_string()]);
        }
        None if ab.enable_dhcp => {
            // 启用时没能记录到任何网关：退回自动获取，避免留下"静态但无网关"的断网状态
            iface_reg::write_dword(key, "EnableDHCP", 1);
            iface_reg::delete(key, "IPAddress");
            iface_reg::delete(key, "SubnetMask");
            iface_reg::delete(key, "DefaultGateway");
            iface_reg::delete(key, "NameServer");
        }
        None => {}
    }
    iface_reg::close(key);

    if backup.adapters.is_empty() {
        // 最后一个网卡已恢复，还原最初的静态路由表并清理备份
        write_persistent_routes(&backup.persistent_routes);
        let _ = std::fs::remove_file(lan_backup_path());
    } else {
        save_backup(&backup)?;
    }

    // 让 Windows 自己重新应用配置（重启网卡）：这样"网络连接"里的网关、
    // DNS、路由度量都会按配置正确刷新——手工补路由的话系统状态页不认。
    let restarted = match restart_device(ab.devinst) {
        Ok(()) => true,
        Err(err) => {
            log_operation(
                "恢复配置:重启网卡失败",
                &Err(err),
                std::time::Duration::from_secs(0),
            );
            false
        }
    };

    let if_index = if ab.if_index != 0 {
        ab.if_index
    } else {
        if_index_of(&ab.guid).unwrap_or(0)
    };

    if restarted && if_index != 0 && gateway.is_some() {
        // 等待系统按配置重新拿到地址与网关（拿到即返回）
        for _ in 0..12 {
            std::thread::sleep(std::time::Duration::from_millis(1000));
            if current_default_gateway(if_index).is_some() {
                break;
            }
        }
    }

    // 兜底：重启失败或系统仍未恢复网关时，手工补一条默认路由保证能上网
    if if_index != 0
        && let Some(gateway) = gateway
        && current_default_gateway(if_index).is_none()
    {
        add_default_route(if_index, gateway)?;
    }
    Ok(())
}

/// 重启网卡（禁用→启用），让 Windows 重新应用注册表里的网络配置。
/// 每步都有超时保护，避免个别设备卡死。
fn restart_device(devinst: u32) -> Result<(), String> {
    match with_timeout(std::time::Duration::from_secs(8), move || {
        set_device_state(devinst, false)
    }) {
        Some(Ok(())) => {}
        Some(Err(e)) => return Err(format!("禁用网卡失败: {e}")),
        None => return Err("禁用网卡超时".to_string()),
    }
    std::thread::sleep(std::time::Duration::from_millis(800));
    match with_timeout(std::time::Duration::from_secs(8), move || {
        set_device_state(devinst, true)
    }) {
        Some(Ok(())) => Ok(()),
        Some(Err(e)) => Err(format!("重新启用网卡失败: {e}")),
        None => Err("重新启用网卡超时".to_string()),
    }
}

/// 等待网卡恢复可用（有 IP 且拿到默认网关），最多等待 wait_secs 秒。
fn wait_for_network(guid: &str, wait_secs: u32) {
    for _ in 0..wait_secs {
        std::thread::sleep(std::time::Duration::from_millis(1000));
        if let Ok((_, adapters)) = query_status()
            && let Some(a) = adapters.iter().find(|a| a.guid.eq_ignore_ascii_case(guid))
            && a.state == "Up"
            && !a.ip.is_empty()
            && !a.gateway.is_empty()
        {
            return;
        }
    }
}

/// 把网卡恢复为自动获取（DHCP）：清除静态配置并让系统重新获取租约。
fn restore_dhcp(guid: &str, devinst: u32) -> Result<(), String> {
    let key = iface_reg::open(guid)?;
    iface_reg::write_dword(key, "EnableDHCP", 1);
    iface_reg::delete(key, "IPAddress");
    iface_reg::delete(key, "SubnetMask");
    iface_reg::delete(key, "DefaultGateway");
    iface_reg::delete(key, "NameServer");
    iface_reg::close(key);

    let if_index = if_index_of(guid).ok_or_else(|| "未找到该网卡接口".to_string())?;

    // 首选：请求 DHCP 续约（IP_ADAPTER_INDEX_MAP 的 Name 必须填适配器名，
    // 否则返回 ERROR_INVALID_PARAMETER(87)）
    let mut map: windows_sys::Win32::NetworkManagement::IpHelper::IP_ADAPTER_INDEX_MAP =
        unsafe { std::mem::zeroed() };
    map.Index = if_index;
    let name: Vec<u16> = guid.encode_utf16().collect();
    if name.len() < map.Name.len() {
        map.Name[..name.len()].copy_from_slice(&name);
    }
    let ret = unsafe { windows_sys::Win32::NetworkManagement::IpHelper::IpRenewAddress(&map) };

    if ret != 0 {
        // 回退：重启网卡强制重新初始化（DHCP 会自动获取租约）
        restart_device(devinst)?;
    }

    wait_for_network(guid, 12);
    Ok(())
}

fn spawn_dhcp_thread(tx: UnboundedSender<Msg>, guid: String, devinst: u32) {
    run_operation(
        tx,
        "恢复自动获取(DHCP)",
        move || {
            restore_dhcp(&guid, devinst)?;

            // DHCP 续约是异步的：轮询等待租约生效（最多 ~10 秒），
            // 否则面板会显示出尚未更新的旧配置
            for _ in 0..10 {
                std::thread::sleep(std::time::Duration::from_millis(1000));
                if let Ok((_, adapters)) = query_status()
                    && let Some(adapter) = adapters
                        .iter()
                        .find(|a| a.guid.eq_ignore_ascii_case(&guid))
                    && adapter.state == "Up"
                    && !adapter.ip.is_empty()
                    && !adapter.gateway.is_empty()
                {
                    break;
                }
            }
            query_status()
        },
        Msg::NetResult,
    );
}

fn spawn_lan_thread(tx: UnboundedSender<Msg>, enable: bool) {
    run_operation(
        tx,
        if enable { "启用局域网模式" } else { "退出局域网模式" },
        move || {
            if enable {
                apply_lan_all()
            } else {
                restore_lan_all()
            }
            .and_then(|_| query_status())
        },
        move |result| Msg::LanResult(result, enable),
    );
}

/// 启用局域网模式：对所有网卡清空默认网关（保留各自 IP）。
fn apply_lan_all() -> Result<(), String> {
    let (_, adapters) = query_status()?;
    let mut ok = 0usize;
    let mut failed = Vec::new();
    for adapter in &adapters {
        match apply_lan_adapter(&adapter.guid, &adapter.name, adapter.devinst) {
            Ok(()) => ok += 1,
            Err(err) => failed.push(err),
        }
    }
    if ok == 0 {
        Err(if failed.is_empty() {
            "没有可应用的网卡".to_string()
        } else {
            format!("局域网模式启用失败: {}", failed.join("; "))
        })
    } else {
        Ok(())
    }
}

/// 退出局域网模式：按备份恢复所有被改动的网卡。
fn restore_lan_all() -> Result<(), String> {
    let mut ok = 0usize;
    let mut failed = Vec::new();
    // 每恢复一个网卡，该网卡即从备份中移除
    loop {
        let Some(backup) = load_backup() else { break };
        let Some(adapter) = backup.adapters.first() else {
            break;
        };
        let guid = adapter.guid.clone();
        match restore_lan_adapter(&guid) {
            Ok(()) => ok += 1,
            Err(err) => {
                failed.push(err);
                break;
            }
        }
    }
    if ok == 0 && !failed.is_empty() {
        Err(format!("恢复失败: {}", failed.join("; ")))
    } else {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// 托盘图标（来自 icon.png）
// ---------------------------------------------------------------------------

/// 托盘图标：可选用色调着色（局域网模式开启时变橙），保留原图 alpha。
fn app_icon(tint: Option<[u8; 3]>) -> tray_icon::Icon {
    let decoded = image::load_from_memory(include_bytes!("../icon.png")).ok();
    if let Some(img) = decoded {
        let mut rgba = image::imageops::resize(
            &img.to_rgba8(),
            32,
            32,
            image::imageops::FilterType::Lanczos3,
        );
        if let Some([r, g, b]) = tint {
            for px in rgba.pixels_mut() {
                px.0[0] = r;
                px.0[1] = g;
                px.0[2] = b;
            }
        }
        let (w, h) = rgba.dimensions();
        if let Ok(icon) = tray_icon::Icon::from_rgba(rgba.into_raw(), w, h) {
            return icon;
        }
    }
    tray_icon::Icon::from_rgba(vec![32; 32 * 32 * 4], 32, 32).expect("valid tray icon")
}

fn tooltip(status: NetStatus, busy: bool, lan_on: bool) -> &'static str {
    if busy {
        "NetCut · 正在切换网络…"
    } else if lan_on {
        "NetCut · 局域网模式已开启"
    } else if status == NetStatus::Connected {
        "NetCut · 网络已连接"
    } else {
        "NetCut · 网络已断开"
    }
}

fn refresh_tray(app: &mut App) {
    let (status, busy, lan_on) = {
        let g = app.global::<NetCut>();
        (g.status, g.busy, !g.lan_adapters.is_empty())
    };
    let tip = tooltip(status, busy, lan_on).to_string();

    // 仅在内容真正变化时更新，避免托盘图标/提示反复重设造成闪烁
    let needs_update = {
        let g = app.global::<NetCut>();
        g.tray_lan_on != Some(lan_on) || g.tray_tooltip != tip
    };
    if !needs_update {
        return;
    }

    if let Some(tray) = &app.global::<NetCut>().tray {
        let tint = if lan_on { Some([0xf5, 0x9e, 0x0b]) } else { None };
        let _ = tray.set_icon(Some(app_icon(tint)));
        let _ = tray.set_tooltip(Some(tip.as_str()));
    }
    {
        let g = app.global_mut::<NetCut>();
        g.tray_lan_on = Some(lan_on);
        g.tray_tooltip = tip;
    }
}

fn build_tray() -> TrayIcon {
    let menu = muda::Menu::new();
    let show = muda::MenuItem::with_id("show", "主窗口", true, None);
    let quit = muda::MenuItem::with_id("quit", "退出", true, None);
    menu.append_items(&[&show, &quit])
        .expect("failed to build tray menu");

    TrayIconBuilder::new()
        .with_tooltip("NetCut · 正在检测网络…")
        .with_icon(app_icon(None))
        .with_menu(Box::new(menu))
        .build()
        .expect("failed to create tray icon")
}

fn spawn_tray_listener(tx: UnboundedSender<Msg>) {
    let tray_rx = tray_icon::TrayIconEvent::receiver().clone();
    let tray_tx = tx.clone();
    std::thread::spawn(move || {
        while let Ok(event) = tray_rx.recv() {
            let msg = match event {
                TrayIconEvent::Click {
                    button,
                    button_state,
                    ..
                } => match (button, button_state) {
                    (MouseButton::Left, MouseButtonState::Up) => Some(Msg::ShowWindow),
                    _ => None,
                },
                _ => None,
            };
            if let Some(msg) = msg {
                let _ = tray_tx.unbounded_send(msg);
            }
        }
    });

    let menu_rx = muda::MenuEvent::receiver().clone();
    std::thread::spawn(move || {
        while let Ok(event) = menu_rx.recv() {
            let msg = match event.id().0.as_str() {
                "show" => Some(Msg::ShowWindow),
                "quit" => Some(Msg::Quit),
                _ => None,
            };
            if let Some(msg) = msg {
                let _ = tx.unbounded_send(msg);
            }
        }
    });
}

// ---------------------------------------------------------------------------
// 消息处理
// ---------------------------------------------------------------------------

fn window_icon() -> Option<std::sync::Arc<image::RgbaImage>> {
    let img = image::load_from_memory(include_bytes!("../icon.png")).ok()?;
    let rgba = image::imageops::resize(
        &img.to_rgba8(),
        32,
        32,
        image::imageops::FilterType::Lanczos3,
    );
    image::RgbaImage::from_raw(32, 32, rgba.into_raw()).map(std::sync::Arc::new)
}

fn open_dashboard(app: &mut App) {
    let options = WindowOptions {
        titlebar: Some(TitlebarOptions {
            title: Some("NetCut".into()),
            ..Default::default()
        }),
        window_bounds: Some(WindowBounds::Windowed(Bounds {
            origin: point(px(160.0), px(160.0)),
            size: size(px(504.0), px(638.0)),
        })),
        icon: window_icon(),
        ..Default::default()
    };
    let handle = open_window(options, app, |window, cx| {
        cx.new(|cx| Dashboard::new(window, cx))
    })
    .expect("failed to open window");
    app.global_mut::<NetCut>().window = Some(handle.0);
}

fn handle_msg(app: &mut App, msg: Msg) {
    match msg {
        Msg::Toggle => {
            {
                let g = app.global_mut::<NetCut>();
                if g.busy {
                    return;
                }
                g.busy = true;
                g.error = None;
            }
            refresh_tray(app);
            app.refresh_windows();
            let tx = app.global::<NetCut>().tx.clone();
            let enable = app.global::<NetCut>().status != NetStatus::Connected;
            spawn_net_thread(tx, Some(enable));
        }
        Msg::SetAdapter { devinst, enable } => {
            {
                let g = app.global_mut::<NetCut>();
                if g.busy {
                    return;
                }
                g.busy = true;
                g.error = None;
            }
            app.refresh_windows();
            let tx = app.global::<NetCut>().tx.clone();
            spawn_adapter_thread(tx, devinst, enable);
        }
        Msg::ShowWindow => {
            let existing = app.global::<NetCut>().window.clone();
            let ok = existing
                .map(|handle| {
                    handle
                        .update(app, |_, window, _| window.activate_window())
                        .is_ok()
                })
                .unwrap_or(false);
            if !ok {
                open_dashboard(app);
            }
        }
        Msg::Quit => app.quit(),
        Msg::Refresh => {
            // 有操作在执行时跳过，避免覆盖操作过程中的中间状态
            if app.global::<NetCut>().busy {
                return;
            }
            let tx = app.global::<NetCut>().tx.clone();
            std::thread::spawn(move || {
                let result = std::panic::catch_unwind(query_status)
                    .unwrap_or_else(|_| Err("刷新状态失败".to_string()));
                let _ = tx.unbounded_send(Msg::RefreshResult(result));
            });
        }
        Msg::RefreshResult(result) => {
            match result {
                Ok((status, adapters)) => {
                    let g = app.global_mut::<NetCut>();
                    g.status = status;
                    g.adapters = adapters;
                    ensure_selection(g);
                }
                // 定时刷新失败不打扰用户（保留原有内容与错误提示）
                Err(_) => return,
            }
            refresh_tray(app);
            app.refresh_windows();
        }
        Msg::RestoreDhcp { guid, devinst } => {
            {
                let g = app.global_mut::<NetCut>();
                if g.busy {
                    return;
                }
                g.busy = true;
                g.error = None;
            }
            app.refresh_windows();
            let tx = app.global::<NetCut>().tx.clone();
            spawn_dhcp_thread(tx, guid, devinst);
        }
        Msg::LanApply { enable } => {
            {
                let g = app.global_mut::<NetCut>();
                if g.busy {
                    return;
                }
                g.busy = true;
                g.error = None;
            }
            app.refresh_windows();
            let tx = app.global::<NetCut>().tx.clone();
            spawn_lan_thread(tx, enable);
        }
        Msg::NetResult(result) => {
            {
                let g = app.global_mut::<NetCut>();
                g.busy = false;
                match result {
                    Ok((status, adapters)) => {
                        g.status = status;
                        g.adapters = adapters;
                        ensure_selection(g);
                        g.error = None;
                    }
                    Err(err) => g.error = Some(err),
                }
            }
            refresh_tray(app);
            app.refresh_windows();
        }
        Msg::LanResult(result, enable) => {
            {
                let g = app.global_mut::<NetCut>();
                g.busy = false;
                match result {
                    Ok((status, adapters)) => {
                        g.status = status;
                        g.adapters = adapters;
                        // 以备份文件为准，反映所有已生效的网卡
                        g.lan_adapters = lan_mode_guids();
                        if !enable {
                            g.lan_adapters.clear();
                        }
                        ensure_selection(g);
                        g.error = None;
                    }
                    Err(err) => g.error = Some(err),
                }
            }
            refresh_tray(app);
            app.refresh_windows();
        }
    }
}

async fn pump_events(app: AsyncApp, mut rx: futures::channel::mpsc::UnboundedReceiver<Msg>) {
    while let Some(msg) = rx.next().await {
        app.update(|app| handle_msg(app, msg));
    }
}

// ---------------------------------------------------------------------------
// 主面板
// ---------------------------------------------------------------------------

/// 选中项失效（网卡消失）时自动回落到第一个网卡。
/// 下拉框分组顺序（同时决定默认选中项）
const GROUP_ORDER: [&str; 5] = ["有线网络", "无线网络", "VPN / 虚拟网卡", "蓝牙", "其他"];

fn group_index(adapter: &AdapterInfo) -> usize {
    let group = adapter_group(adapter);
    GROUP_ORDER.iter().position(|g| *g == group).unwrap_or(4)
}

/// 按下拉框显示顺序排序（组内保持原有顺序）
fn ordered_adapters(adapters: &[AdapterInfo]) -> Vec<AdapterInfo> {
    let mut list = adapters.to_vec();
    list.sort_by_key(group_index);
    list
}

fn ensure_selection(g: &mut NetCut) {
    // 清理已不存在的网卡 GUID（陈旧项会让"是否已开启"判断错乱）
    g.lan_adapters
        .retain(|guid| g.adapters.iter().any(|a| &a.guid == guid));

    let valid = g
        .selected
        .as_ref()
        .map(|guid| g.adapters.iter().any(|a| &a.guid == guid))
        .unwrap_or(false);
    if !valid {
        // 默认选中下拉框里的第 0 个（即分组后的第一张网卡）
        g.selected = ordered_adapters(&g.adapters)
            .first()
            .map(|a| a.guid.clone());
    }
}

struct Dashboard {
    combo: Entity<ComboboxState<AdapterDelegate>>,
    signature: String,
}

/// 下拉框中的一个网卡条目
#[derive(Clone)]
struct AdapterItem {
    guid: String,
    name: String,
    desc: String,
}

impl SearchableListItem for AdapterItem {
    type Value = String;

    fn title(&self) -> gpui_kit::SharedString {
        self.name.clone().into()
    }

    fn value(&self) -> &String {
        &self.guid
    }

    fn matches(&self, query: &str) -> bool {
        let q = query.to_lowercase();
        self.name.to_lowercase().contains(&q) || self.desc.to_lowercase().contains(&q)
    }

    fn render(&self, _: &mut Window, cx: &mut App) -> impl IntoElement {
        div()
            .flex()
            .flex_col()
            .child(div().child(self.name.clone()))
            .child(
                div()
                    .text_xs()
                    .text_color(cx.theme().muted_foreground)
                    .child(self.desc.clone()),
            )
    }
}

type AdapterDelegate = SearchableVec<SearchableGroup<AdapterItem>>;

/// 按网卡类型分组（有线 / 无线 / VPN / 蓝牙 / 其他）
fn adapter_group(a: &AdapterInfo) -> &'static str {
    let s = format!("{} {}", a.name, a.desc).to_lowercase();
    if s.contains("wi-fi") || s.contains("wireless") || s.contains("wlan") || s.contains("802.11") {
        "无线网络"
    } else if s.contains("bluetooth") || s.contains("蓝牙") {
        "蓝牙"
    } else if s.contains("vpn") || s.contains("ssl") || s.contains("virtual") {
        "VPN / 虚拟网卡"
    } else if s.contains("ethernet")
        || s.contains("gbe")
        || s.contains("以太网")
        || s.contains("lan")
    {
        "有线网络"
    } else {
        "其他"
    }
}

fn build_adapter_delegate(adapters: &[AdapterInfo]) -> AdapterDelegate {
    const GROUP_ORDER: [&str; 5] = ["有线网络", "无线网络", "VPN / 虚拟网卡", "蓝牙", "其他"];
    let mut groups: Vec<SearchableGroup<AdapterItem>> = GROUP_ORDER
        .iter()
        .map(|title| SearchableGroup::new(*title))
        .collect();
    for adapter in adapters {
        let index = group_index(adapter);
        groups[index] = groups[index].clone().item(AdapterItem {
            guid: adapter.guid.clone(),
            name: adapter.name.clone(),
            desc: adapter.desc.clone(),
        });
    }
    SearchableVec::new(
        groups
            .into_iter()
            .filter(|g| !g.items.is_empty())
            .collect::<Vec<_>>(),
    )
}

fn adapter_signature(adapters: &[AdapterInfo]) -> String {
    adapters
        .iter()
        .map(|a| format!("{}|{}|{}", a.guid, a.name, a.desc))
        .collect::<Vec<_>>()
        .join("#")
}

impl Dashboard {
    fn new(window: &mut Window, cx: &mut Context<Self>) -> Self {
        let adapters = query_status()
            .map(|(_, adapters)| adapters)
            .unwrap_or_default();
        let delegate = build_adapter_delegate(&adapters);
        let combo = cx.new(|cx| ComboboxState::new(delegate, Vec::new(), window, cx));
        Self {
            combo,
            signature: adapter_signature(&adapters),
        }
    }
}

impl Render for Dashboard {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let (status, busy, lan_adapters, adapters, mut selected, error) = {
            let g = cx.global::<NetCut>();
            (
                g.status,
                g.busy,
                g.lan_adapters.clone(),
                g.adapters.clone(),
                g.selected.clone(),
                g.error.clone(),
            )
        };

        // 网卡列表变化时刷新下拉框数据源
        let signature = adapter_signature(&adapters);
        if signature != self.signature {
            self.signature = signature;
            let delegate = build_adapter_delegate(&adapters);
            self.combo
                .update(cx, |state, cx| state.set_items(delegate, window, cx));
        }

        // 下拉框与全局选中项双向同步
        let combo_selected = self.combo.read(cx).selected_value();
        match &combo_selected {
            Some(guid) => {
                if selected.as_ref() != Some(guid) {
                    selected = Some(guid.clone());
                    cx.global_mut::<NetCut>().selected = Some(guid.clone());
                }
            }
            None => {
                if let Some(guid) = selected.clone() {
                    self.combo.update(cx, |state, cx| {
                        state.set_selected_values(&[guid], window, cx)
                    });
                }
            }
        }

        let (status_text, color): (&str, gpui_kit::Hsla) = if busy {
            ("正在切换…", gpui_kit::rgb(0xf5_9e_0b).into())
        } else if status == NetStatus::Connected {
            ("网络已连接", gpui_kit::rgb(0x22_c5_5e).into())
        } else {
            ("网络已断开", gpui_kit::rgb(0xef_44_44).into())
        };
        let (icon, button_label) = if status == NetStatus::Connected && !busy {
            (IconName::Globe, "一键断网")
        } else {
            (IconName::Globe, "一键联网")
        };
        let up_count = adapters.iter().filter(|a| a.state == "Up").count();

        // 局域网模式状态（全局）
        let lan_total = adapters.len();
        let lan_active = adapters
            .iter()
            .filter(|a| lan_adapters.contains(&a.guid))
            .count();
        let lan_any_active = lan_active > 0;
        let lan_icon_color: gpui_kit::Hsla = gpui_kit::rgb(0xf5_9e_0b).into();
        let (lan_status_text, lan_status_color): (String, gpui_kit::Hsla) = if lan_total > 0
            && lan_active == lan_total
        {
            ("局域网模式：已启用".to_string(), gpui_kit::rgb(0x22_c5_5e).into())
        } else if lan_active > 0 {
            (
                format!("局域网模式：部分启用（{lan_active}/{lan_total}）"),
                gpui_kit::rgb(0xf5_9e_0b).into(),
            )
        } else {
            (
                "局域网模式：已关闭".to_string(),
                cx.theme().muted_foreground,
            )
        };

        // 第一部分：状态头部（顶部对齐）
        let mut root = div()
            .flex()
            .flex_col()
            .size_full()
            .gap_3()
            .p_6()
            .bg(cx.theme().background)
            .text_color(cx.theme().foreground)
            .child(
                div()
                    .flex()
                    .flex_col()
                    .items_center()
                    .gap_2()
                    .child(
                        Icon::new(icon.clone())
                            .size_10()
                            .text_color(if lan_any_active { lan_icon_color } else { color }),
                    )
                    .child(div().text_2xl().font_semibold().child(status_text))
                    .child(
                        div()
                            .text_sm()
                            .text_color(cx.theme().muted_foreground)
                            .child(format!(
                                "共 {} 个网络适配器 · {} 个已连接",
                                adapters.len(),
                                up_count
                            )),
                    )
                    .child(
                        div()
                            .rounded_full()
                            .px_3()
                            .py_1()
                            .text_xs()
                            .text_color(lan_status_color)
                            .child(lan_status_text.clone()),
                    ),
            );

        if let Some(err) = error {
            root = root.child(
                div()
                    .w_full()
                    .rounded_md()
                    .p_2()
                    .text_sm()
                    .bg(gpui_kit::rgb(0x45_1a_1a))
                    .text_color(gpui_kit::rgb(0xfc_a5_a5))
                    .child(err),
            );
        }

        if !adapters.is_empty() {
            // 第二部分：网卡下拉选择（固定在详情面板上方，不随滚动移动）
            let selected_adapter = adapters
                .iter()
                .find(|a| Some(&a.guid) == selected.as_ref())
                .cloned();

            root = root.child(
                div()
                    .w_full()
                    .flex_shrink_0()
                    .child(
                        Combobox::new(&self.combo)
                            .search_placeholder("搜索网卡…")
                            .cleanable(false)
                            .w_full(),
                    ),
            );

            // 第三部分：选中网卡的详情（自适应高度，超出内部滚动）
            if let Some(adapter) = selected_adapter {
                let dot = if adapter.state == "Up" {
                    gpui_kit::rgb(0x22_c5_5e)
                } else if adapter.state == "Disabled" {
                    gpui_kit::rgb(0xef_44_44)
                } else {
                    gpui_kit::rgb(0x94_a3_b8)
                };
                let enabled = adapter.state != "Disabled";
                let action_label = if enabled { "断开" } else { "连接" };
                let devinst = adapter.devinst;
                let guid = adapter.guid.clone();
                let in_lan_mode = lan_adapters.contains(&adapter.guid);
                let lan_badge_color: gpui_kit::Hsla = if in_lan_mode {
                    gpui_kit::rgb(0x22_c5_5e).into()
                } else {
                    cx.theme().muted_foreground
                };
                let detail = |label: &'static str, value: String, muted: bool| {
                    let text_color = if muted {
                        cx.theme().muted_foreground
                    } else {
                        cx.theme().foreground
                    };
                    div()
                        .flex()
                        .items_center()
                        .gap_2()
                        .child(
                            div()
                                .w(px(64.0))
                                .flex_shrink_0()
                                .text_color(cx.theme().muted_foreground)
                                .child(label),
                        )
                        .child(
                            div()
                                .flex_1()
                                .min_w(px(0.0))
                                .text_color(text_color)
                                .child(if value.is_empty() {
                                    "—".to_string()
                                } else {
                                    value
                                }),
                        )
                };

                root = root.child(
                    div()
                        .w_full()
                        .flex_1()
                        .min_h(px(100.0))
                        .id("detail-scroll")
                        .overflow_y_scroll()
                        .flex()
                        .flex_col()
                        .gap_2()
                        .rounded_lg()
                        .p_3()
                        .bg(cx.theme().secondary)
                        .text_sm()
                        .child(
                            div()
                                .flex()
                                .items_center()
                                .gap_2()
                                .child(div().size_2().rounded_full().bg(dot))
                                .child(
                                    div()
                                        .flex_1()
                                        .min_w(px(0.0))
                                        .child(
                                            div()
                                                .text_color(cx.theme().muted_foreground)
                                                .child(adapter.desc.clone()),
                                        ),
                                )
                                .child(
                                    div()
                                        .flex_shrink_0()
                                        .text_color(cx.theme().muted_foreground)
                                        .child(adapter.state),
                                )
                                .child(
                                    Button::new(format!("adapter-{}", adapter.devinst))
                                        .label(action_label)
                                        .small()
                                        .disabled(busy)
                                        .flex_shrink_0()
                                        .on_click(cx.listener(move |_, _, _, cx| {
                                            let tx = cx.global::<NetCut>().tx.clone();
                                            let _ = tx.unbounded_send(Msg::SetAdapter {
                                                devinst,
                                                enable: !enabled,
                                            });
                                        })),
                                ),
                        )
                        .child(detail("IP 地址", adapter.ip.clone(), adapter.ip.is_empty()))
                        .child(detail("子网掩码", adapter.mask.clone(), adapter.mask.is_empty()))
                        .child(detail(
                            "默认网关",
                            if adapter.gateway.is_empty() {
                                "未设置（仅局域网可访问）".to_string()
                            } else {
                                adapter.gateway.clone()
                            },
                            adapter.gateway.is_empty(),
                        ))
                        .child(detail("DNS", adapter.dns.clone(), adapter.dns.is_empty()))
                        .child(
                            div()
                                .flex()
                                .items_center()
                                .gap_2()
                                .child(
                                    div()
                                        .flex_1()
                                        .text_xs()
                                        .text_color(lan_badge_color)
                                        .child(if in_lan_mode {
                                            "局域网模式：已启用（网关已清空）"
                                        } else {
                                            "局域网模式：未启用"
                                        }),
                                )
                                .child(
                                    Button::new(format!("dhcp-{}", adapter.guid))
                                        .label("恢复自动获取(DHCP)")
                                        .small()
                                        .flex_shrink_0()
                                        .disabled(busy)
                                        .on_click(cx.listener(move |_, _, _, cx| {
                                            let tx = cx.global::<NetCut>().tx.clone();
                                            let _ = tx.unbounded_send(Msg::RestoreDhcp {
                                                devinst,
                                                guid: guid.clone(),
                                            });
                                        })),
                                ),
                        ),
                );
            }
        }

        // 第四部分：操作按钮（底部对齐）
        let lan_all_active = lan_total > 0 && lan_active == lan_total;
        // 点击即开关：有任一网卡已开启 → 关闭；否则 → 全部开启
        let lan_click_enables = !lan_any_active;
        let lan_button_label = if lan_all_active {
            "局域网模式：已开启".to_string()
        } else if lan_any_active {
            format!("局域网模式：已开启（{lan_active}/{lan_total}）")
        } else {
            "局域网模式：已关闭".to_string()
        };
        let lan_busy = busy;
        root.child(
            div()
                .w_full()
                .flex()
                .flex_col()
                .gap_2()
                .child(
                    Button::new("toggle")
                        .primary()
                        .label(button_label)
                        .icon(icon)
                        .disabled(busy)
                        .w_full()
                        .on_click(cx.listener(|_, _, _, cx| {
                            let tx = cx.global::<NetCut>().tx.clone();
                            let _ = tx.unbounded_send(Msg::Toggle);
                        })),
                )
                .child({
                    let lan_button = Button::new("lan-mode")
                        .label(lan_button_label)
                        .w_full()
                        .disabled(lan_busy);
                    // 局域网模式开启时按钮变橙色
                    let lan_button = if lan_any_active {
                        lan_button
                            .bg(gpui_kit::rgb(0xf5_9e_0b))
                            .text_color(gpui_kit::rgb(0x1f_29_37))
                    } else {
                        lan_button
                    };
                    lan_button.on_click(cx.listener(move |_, _, _, cx| {
                        let tx = cx.global::<NetCut>().tx.clone();
                        let _ = tx.unbounded_send(Msg::LanApply {
                            enable: lan_click_enables,
                        });
                    }))
                })
                .child(
                    div()
                        .text_xs()
                        .text_center()
                        .text_color(cx.theme().muted_foreground)
                        .child("托盘图标：左键显示主窗口 · 右键弹出功能菜单（含退出）"),
                ),
        )
    }
}

// ---------------------------------------------------------------------------
// 管理员提权
// ---------------------------------------------------------------------------

fn ensure_admin() {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::UI::Shell::ShellExecuteW;
    use windows_sys::Win32::UI::WindowsAndMessaging::{MB_ICONWARNING, MB_OK, MessageBoxW};

    let is_admin = unsafe { windows_sys::Win32::UI::Shell::IsUserAnAdmin() } != 0;
    if is_admin {
        return;
    }

    let wide = |s: &str| {
        s.encode_utf16()
            .chain(std::iter::once(0))
            .collect::<Vec<u16>>()
    };
    let exe = std::env::current_exe().expect("current exe path");
    let exe_w = exe
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<u16>>();

    let ret = unsafe {
        ShellExecuteW(
            std::ptr::null_mut(),
            wide("runas").as_ptr(),
            exe_w.as_ptr(),
            std::ptr::null(),
            std::ptr::null(),
            10, // SW_SHOWDEFAULT
        )
    };

    if ret as isize <= 32 {
        let text = wide("NetCut 需要管理员权限才能开关网络适配器，请以管理员身份运行。");
        let caption = wide("NetCut");
        unsafe {
            MessageBoxW(
                std::ptr::null_mut(),
                text.as_ptr(),
                caption.as_ptr(),
                MB_ICONWARNING | MB_OK,
            );
        }
        std::process::exit(1);
    }
    // 提权后的新进程已启动，当前进程退出
    std::process::exit(0);
}

// ---------------------------------------------------------------------------
// 入口
// ---------------------------------------------------------------------------

fn main() {
    std::panic::set_hook(Box::new(|info| {
        let msg = format!("{info}\n{:#?}", std::backtrace::Backtrace::force_capture());
        let log = std::env::temp_dir().join("netcut-panic.log");
        let _ = std::fs::write(&log, &msg);
        eprintln!("{msg}");
    }));

    ensure_admin();

    application().with_assets(assets::Assets).run(|cx| {
        gpui_kit::init(cx);
        Theme::change(ThemeMode::Dark, None, cx);
        // 关闭窗口只隐藏到托盘，不退出程序；仅通过托盘菜单/按钮显式退出
        cx.set_quit_mode(QuitMode::Explicit);

        let (tx, rx) = futures::channel::mpsc::unbounded::<Msg>();
        let tray = build_tray();
        spawn_tray_listener(tx.clone());

        cx.set_global(NetCut {
            tx: tx.clone(),
            tray: Some(tray),
            tray_lan_on: None,
            tray_tooltip: String::new(),
            status: NetStatus::Unknown,
            busy: true,
            lan_adapters: lan_mode_guids(),
            selected: None,
            adapters: Vec::new(),
            error: None,
            window: None,
        });

        spawn_net_thread(tx.clone(), None);
        // 定时异步刷新：每 5 秒重新读取网卡与地址信息（操作进行中会自动跳过）
        {
            let tx = tx.clone();
            std::thread::spawn(move || loop {
                std::thread::sleep(std::time::Duration::from_secs(5));
                if tx.unbounded_send(Msg::Refresh).is_err() {
                    break; // 主循环已退出
                }
            });
        }
        open_dashboard(cx);
        cx.spawn(|app: &mut AsyncApp| {
            let app = app.clone();
            pump_events(app, rx)
        })
        .detach();
    });
}
