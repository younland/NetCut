//! Windows 过滤平台（WFP）接口级流量拦截。
//!
//! 局域网模式用它来"只放行局域网网段、拦截其余流量"，而不改动网卡的
//! 网关/IP/DNS 配置：过滤器挂在指定接口上，是会话级临时规则——程序退出
//! 或异常终止时由系统自动撤销，不会残留拦截。

use std::sync::atomic::{AtomicU64, Ordering};
use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform as w;
use windows_sys::Win32::System::Rpc::RPC_C_AUTHN_WINNT;
use windows_sys::core::GUID;

/// 本工具自己的子层键（固定值，便于在系统里识别）
const SUBLAYER_KEY: GUID = GUID::from_u128(0x6f5b1c2d_9e34_4a71_9c8b_2d5e7fa104c9);

/// 过滤器键序号：每次添加都要唯一
static KEY_SEQ: AtomicU64 = AtomicU64::new(1);

fn next_key() -> GUID {
    let seq = KEY_SEQ.fetch_add(1, Ordering::Relaxed);
    GUID::from_u128(0x9a1d4f77_0000_4000_9000_0000_0000_0000u128 | seq as u128)
}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn mask_from_prefix(prefix: u8) -> u32 {
    let prefix = prefix.min(32);
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    }
}

/// 需要放行的 IPv4 网段：(网络地址, 前缀长度)
fn permit_v4(local: Option<(u32, u8)>) -> Vec<(u32, u8)> {
    let mut subnets = vec![
        // 本地链路（DHCP/APIPA）、多播（mDNS/SSDP 等）、广播
        (u32::from_be_bytes([169, 254, 0, 0]), 16),
        (u32::from_be_bytes([224, 0, 0, 0]), 4),
        (u32::from_be_bytes([255, 255, 255, 255]), 32),
    ];
    if let Some((addr, prefix)) = local {
        let mask = mask_from_prefix(prefix);
        subnets.push((addr & mask, prefix.min(32)));
    }
    subnets
}

/// 需要放行的 IPv6 网段：链路本地与多播
const PERMIT_V6: [([u8; 16], u8); 2] = [
    ([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], 10),
    ([0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], 8),
];

/// 过滤会话：Drop 时删除全部过滤器并关闭引擎。
pub struct LanFilterSession {
    engine: HANDLE,
    filter_ids: Vec<u64>,
    /// 动态白名单规则引用的地址掩码（需与规则同生命周期）
    v4_masks: Vec<Box<w::FWP_V4_ADDR_AND_MASK>>,
    v6_masks: Vec<Box<w::FWP_V6_ADDR_AND_MASK>>,
    /// 非致命警告（例如该环境不支持 IPv6 过滤规则）
    warnings: Vec<String>,
}

// 句柄只在创建它的线程（界面线程）里使用
impl LanFilterSession {
    /// 建立过程中出现的非致命警告
    pub fn warnings(&self) -> &[String] {
        &self.warnings
    }

    /// 为命中的白名单域名放行其解析到的 IP（不带接口条件，作用于所有网卡）
    pub fn permit_ip(&mut self, ip: std::net::IpAddr, name: &str) -> Result<u64, String> {
        let conditions;
        let layers: &[GUID];
        let mut v4 = Box::new(w::FWP_V4_ADDR_AND_MASK { addr: 0, mask: u32::MAX });
        let mut v6 = Box::new(w::FWP_V6_ADDR_AND_MASK {
            addr: [0u8; 16],
            prefixLength: 128,
        });
        match ip {
            std::net::IpAddr::V4(addr) => {
                v4.addr = u32::from_ne_bytes(addr.octets());
                self.v4_masks.push(v4);
                let mask_ptr = self.v4_masks.last().unwrap().as_ref() as *const _ as *mut _;
                conditions = vec![w::FWPM_FILTER_CONDITION0 {
                    fieldKey: w::FWPM_CONDITION_IP_REMOTE_ADDRESS,
                    matchType: w::FWP_MATCH_EQUAL,
                    conditionValue: w::FWP_CONDITION_VALUE0 {
                        r#type: w::FWP_V4_ADDR_MASK,
                        Anonymous: w::FWP_CONDITION_VALUE0_0 {
                            v4AddrMask: mask_ptr,
                        },
                    },
                }];
                layers = &[
                    w::FWPM_LAYER_ALE_AUTH_CONNECT_V4,
                    w::FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
                ];
            }
            std::net::IpAddr::V6(addr) => {
                v6.addr = addr.octets();
                self.v6_masks.push(v6);
                let mask_ptr = self.v6_masks.last().unwrap().as_ref() as *const _ as *mut _;
                conditions = vec![w::FWPM_FILTER_CONDITION0 {
                    fieldKey: w::FWPM_CONDITION_IP_REMOTE_ADDRESS,
                    matchType: w::FWP_MATCH_EQUAL,
                    conditionValue: w::FWP_CONDITION_VALUE0 {
                        r#type: w::FWP_V6_ADDR_MASK,
                        Anonymous: w::FWP_CONDITION_VALUE0_0 {
                            v6AddrMask: mask_ptr,
                        },
                    },
                }];
                layers = &[
                    w::FWPM_LAYER_ALE_AUTH_CONNECT_V6,
                    w::FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
                ];
            }
        }

        let label = format!("NetCut 白名单 {name}");
        let mut first_id = None;
        for layer in layers {
            match unsafe {
                add_filter(
                    self.engine,
                    layer,
                    w::FWP_ACTION_PERMIT,
                    WEIGHT_PERMIT_WHITELIST,
                    &conditions,
                    &label,
                )
            } {
                Ok(id) => {
                    self.filter_ids.push(id);
                    first_id.get_or_insert(id);
                }
                Err(err) => return Err(err),
            }
        }
        first_id.ok_or_else(|| "白名单放行规则创建失败".to_string())
    }

    /// 撤销一条（或一组）放行规则
    pub fn revoke(&mut self, id: u64) {
        self.filter_ids.retain(|existing| {
            if *existing == id {
                unsafe { w::FwpmFilterDeleteById0(self.engine, *existing) };
                false
            } else {
                true
            }
        });
    }
}

impl Drop for LanFilterSession {
    fn drop(&mut self) {
        unsafe {
            for id in &self.filter_ids {
                w::FwpmFilterDeleteById0(self.engine, *id);
            }
            w::FwpmEngineClose0(self.engine);
        }
    }
}

/// 过滤器权重：数值越大越先匹配。显式指定避免依赖自动权重推断：
/// 白名单放行(32) > 局域网放行(16) > 拦截(1)
const WEIGHT_BLOCK: u64 = 1;
const WEIGHT_PERMIT_DNS: u64 = 8;
const WEIGHT_PERMIT_LAN: u64 = 16;
const WEIGHT_PERMIT_WHITELIST: u64 = 32;

/// 添加一条过滤器（条件引用的数据由调用方保持存活）
unsafe fn add_filter(
    engine: HANDLE,
    layer: &GUID,
    action: u32,
    weight: u64,
    conditions: &[w::FWPM_FILTER_CONDITION0],
    name: &str,
) -> Result<u64, String> {
    let mut display_name = wide(name);
    let mut filter: w::FWPM_FILTER0 = unsafe { std::mem::zeroed() };
    filter.filterKey = next_key();
    filter.displayData = w::FWPM_DISPLAY_DATA0 {
        name: display_name.as_mut_ptr(),
        description: std::ptr::null_mut(),
    };
    filter.layerKey = *layer;
    filter.subLayerKey = SUBLAYER_KEY;
    let mut weight_value = weight;
    filter.weight = w::FWP_VALUE0 {
        r#type: w::FWP_UINT64,
        Anonymous: w::FWP_VALUE0_0 {
            uint64: &mut weight_value,
        },
    };
    filter.numFilterConditions = conditions.len() as u32;
    filter.filterCondition = conditions.as_ptr() as *mut w::FWPM_FILTER_CONDITION0;
    filter.action = w::FWPM_ACTION0 {
        r#type: action,
        Anonymous: unsafe { std::mem::zeroed() },
    };

    let mut id = 0u64;
    let ret = unsafe { w::FwpmFilterAdd0(engine, &filter, std::ptr::null_mut(), &mut id) };
    if ret != 0 {
        return Err(format!("添加过滤规则失败（{name}，错误 {ret}）"));
    }
    Ok(id)
}

/// 启用局域网模式：在指定接口上只放行局域网网段，其余流量全部拦截。
///
/// 入参：`(接口 LUID, 该接口当前 IPv4 地址与前缀长度)`。
pub fn enable(interfaces: &[(u64, Option<(u32, u8)>)]) -> Result<LanFilterSession, String> {
    if interfaces.is_empty() {
        return Err("没有可应用局域网模式的网卡".to_string());
    }

    let mut engine: HANDLE = std::ptr::null_mut();
    let mut session: w::FWPM_SESSION0 = unsafe { std::mem::zeroed() };
    session.flags = w::FWPM_SESSION_FLAG_DYNAMIC; // 会话结束即自动清理
    let ret = unsafe {
        w::FwpmEngineOpen0(
            std::ptr::null(),
            RPC_C_AUTHN_WINNT,
            std::ptr::null(),
            &session,
            &mut engine,
        )
    };
    if ret != 0 {
        return Err(format!("打开网络过滤引擎失败（错误 {ret}）"));
    }

    let mut sublayer: w::FWPM_SUBLAYER0 = unsafe { std::mem::zeroed() };
    sublayer.subLayerKey = SUBLAYER_KEY;
    let mut sublayer_name = wide("NetCut LAN mode");
    sublayer.displayData = w::FWPM_DISPLAY_DATA0 {
        name: sublayer_name.as_mut_ptr(),
        description: std::ptr::null_mut(),
    };
    sublayer.weight = 0x8000;
    let ret = unsafe { w::FwpmSubLayerAdd0(engine, &sublayer, std::ptr::null_mut()) };
    if ret != 0 {
        unsafe { w::FwpmEngineClose0(engine) };
        return Err(format!("注册过滤子层失败（错误 {ret}）"));
    }

    // 条件里用到的数据（LUID、地址掩码）必须存活到 FwpmFilterAdd0 返回
    let mut luids: Vec<Box<u64>> = Vec::new();
    let mut v4_masks: Vec<Box<w::FWP_V4_ADDR_AND_MASK>> = Vec::new();
    let mut v6_masks: Vec<Box<w::FWP_V6_ADDR_AND_MASK>> = Vec::new();
    let mut filter_ids: Vec<u64> = Vec::new();
    let mut warnings: Vec<String> = Vec::new();

    let build = |luids: &mut Vec<Box<u64>>,
                 v4_masks: &mut Vec<Box<w::FWP_V4_ADDR_AND_MASK>>,
                 v6_masks: &mut Vec<Box<w::FWP_V6_ADDR_AND_MASK>>,
                 filter_ids: &mut Vec<u64>,
                 warnings: &mut Vec<String>|
     -> Result<(), String> {
        for (luid, local_v4) in interfaces {
            luids.push(Box::new(*luid));
            let luid_ptr = luids.last().unwrap().as_ref() as *const u64 as *mut u64;
            let interface_cond = w::FWPM_FILTER_CONDITION0 {
                fieldKey: w::FWPM_CONDITION_IP_LOCAL_INTERFACE,
                matchType: w::FWP_MATCH_EQUAL,
                conditionValue: w::FWP_CONDITION_VALUE0 {
                    r#type: w::FWP_UINT64,
                    Anonymous: w::FWP_CONDITION_VALUE0_0 {
                        uint64: luid_ptr,
                    },
                },
            };
            let remote_v4 = |mask_ptr: *mut w::FWP_V4_ADDR_AND_MASK| w::FWPM_FILTER_CONDITION0 {
                fieldKey: w::FWPM_CONDITION_IP_REMOTE_ADDRESS,
                matchType: w::FWP_MATCH_EQUAL,
                conditionValue: w::FWP_CONDITION_VALUE0 {
                    r#type: w::FWP_V4_ADDR_MASK,
                    Anonymous: w::FWP_CONDITION_VALUE0_0 { v4AddrMask: mask_ptr },
                },
            };
            // 注意：ALE 层没有 *_V6 专用条件，用通用的远端地址条件 + v6 掩码类型
            let remote_v6 = |mask_ptr: *mut w::FWP_V6_ADDR_AND_MASK| w::FWPM_FILTER_CONDITION0 {
                fieldKey: w::FWPM_CONDITION_IP_REMOTE_ADDRESS,
                matchType: w::FWP_MATCH_EQUAL,
                conditionValue: w::FWP_CONDITION_VALUE0 {
                    r#type: w::FWP_V6_ADDR_MASK,
                    Anonymous: w::FWP_CONDITION_VALUE0_0 { v6AddrMask: mask_ptr },
                },
            };

            for layer in [
                w::FWPM_LAYER_ALE_AUTH_CONNECT_V4,
                w::FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
            ] {
                // 放行局域网网段（条件更具体，权重高于 0.0.0.0/0）
                for (addr, prefix) in permit_v4(*local_v4) {
                    v4_masks.push(Box::new(w::FWP_V4_ADDR_AND_MASK {
                        addr,
                        mask: mask_from_prefix(prefix),
                    }));
                    let mask_ptr = v4_masks.last().unwrap().as_ref() as *const _ as *mut _;
                    let conditions = vec![interface_cond, remote_v4(mask_ptr)];
                    filter_ids.push(unsafe {
                        add_filter(
                            engine,
                            &layer,
                            w::FWP_ACTION_PERMIT,
                            WEIGHT_PERMIT_LAN,
                            &conditions,
                            "NetCut 允许局域网",
                        )?
                    });
                }

                // 其余一律拦截
                v4_masks.push(Box::new(w::FWP_V4_ADDR_AND_MASK { addr: 0, mask: 0 }));
                let any_ptr = v4_masks.last().unwrap().as_ref() as *const _ as *mut _;
                let conditions = vec![interface_cond, remote_v4(any_ptr)];
                filter_ids.push(unsafe {
                    add_filter(
                        engine,
                        &layer,
                        w::FWP_ACTION_BLOCK,
                        WEIGHT_BLOCK,
                        &conditions,
                        "NetCut 拦截非局域网",
                    )?
                });
            }

            // IPv6 规则为"尽力而为"：某些环境（无 v6 栈等）可能不支持，
            // 失败只记警告，不影响 IPv4 的拦截效果
            for layer in [
                w::FWPM_LAYER_ALE_AUTH_CONNECT_V6,
                w::FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
            ] {
                for (addr, prefix) in PERMIT_V6 {
                    v6_masks.push(Box::new(w::FWP_V6_ADDR_AND_MASK {
                        addr,
                        prefixLength: prefix,
                    }));
                    let mask_ptr = v6_masks.last().unwrap().as_ref() as *const _ as *mut _;
                    let conditions = vec![interface_cond, remote_v6(mask_ptr)];
                    match unsafe {
                        add_filter(
                            engine,
                            &layer,
                            w::FWP_ACTION_PERMIT,
                            WEIGHT_PERMIT_LAN,
                            &conditions,
                            "NetCut 允许局域网 v6",
                        )
                    } {
                        Ok(id) => filter_ids.push(id),
                        Err(err) => warnings.push(err),
                    }
                }

                v6_masks.push(Box::new(w::FWP_V6_ADDR_AND_MASK {
                    addr: [0u8; 16],
                    prefixLength: 0,
                }));
                let any_ptr = v6_masks.last().unwrap().as_ref() as *const _ as *mut _;
                let conditions = vec![interface_cond, remote_v6(any_ptr)];
                match unsafe {
                    add_filter(
                        engine,
                        &layer,
                        w::FWP_ACTION_BLOCK,
                        WEIGHT_BLOCK,
                        &conditions,
                        "NetCut 拦截非局域网 v6",
                    )
                } {
                    Ok(id) => filter_ids.push(id),
                    Err(err) => warnings.push(err),
                }
            }
        }
        // 放行 DNS 查询（UDP/TCP 53，不限接口）：白名单需要向上游解析域名，
        // 上游可能是公共 DNS，不能把它一起拦掉
        for layer in [
            w::FWPM_LAYER_ALE_AUTH_CONNECT_V4,
            w::FWPM_LAYER_ALE_AUTH_CONNECT_V6,
        ] {
            for protocol in [17u8, 6u8] {
                let conditions = vec![
                    w::FWPM_FILTER_CONDITION0 {
                        fieldKey: w::FWPM_CONDITION_IP_PROTOCOL,
                        matchType: w::FWP_MATCH_EQUAL,
                        conditionValue: w::FWP_CONDITION_VALUE0 {
                            r#type: w::FWP_UINT8,
                            Anonymous: w::FWP_CONDITION_VALUE0_0 { uint8: protocol },
                        },
                    },
                    w::FWPM_FILTER_CONDITION0 {
                        fieldKey: w::FWPM_CONDITION_IP_REMOTE_PORT,
                        matchType: w::FWP_MATCH_EQUAL,
                        conditionValue: w::FWP_CONDITION_VALUE0 {
                            r#type: w::FWP_UINT16,
                            Anonymous: w::FWP_CONDITION_VALUE0_0 { uint16: 53 },
                        },
                    },
                ];
                match unsafe {
                    add_filter(
                        engine,
                        &layer,
                        w::FWP_ACTION_PERMIT,
                        WEIGHT_PERMIT_DNS,
                        &conditions,
                        "NetCut 允许 DNS",
                    )
                } {
                    Ok(id) => filter_ids.push(id),
                    Err(err) => warnings.push(err),
                }
            }
        }
        Ok(())
    };

    match build(
        &mut luids,
        &mut v4_masks,
        &mut v6_masks,
        &mut filter_ids,
        &mut warnings,
    ) {
        Ok(()) => Ok(LanFilterSession {
            engine,
            filter_ids,
            v4_masks: Vec::new(),
            v6_masks: Vec::new(),
            warnings,
        }),
        Err(err) => {
            unsafe {
                for id in &filter_ids {
                    w::FwpmFilterDeleteById0(engine, *id);
                }
                w::FwpmEngineClose0(engine);
            }
            Err(err)
        }
    }
}
