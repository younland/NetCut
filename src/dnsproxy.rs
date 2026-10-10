//! 极简 DNS 转发器：只监听本机 127.0.0.1:53，把查询原样转发给上游，
//! 并解析响应里的 A/AAAA 记录——若查询的域名命中白名单，则把解析结果
//! 交给回调（用于在 WFP 上临时放行这些 IP）。

use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use crate::whitelist::Whitelist;

/// 一次解析结果：命中的地址与最小 TTL
#[derive(Clone, Debug)]
pub struct Resolved {
    pub addresses: Vec<IpAddr>,
    pub ttl: u32,
}

/// 运行中的转发器；Drop 时通知线程退出
pub struct DnsProxy {
    running: Arc<AtomicBool>,
}

impl Drop for DnsProxy {
    fn drop(&mut self) {
        self.running.store(false, Ordering::Relaxed);
    }
}

impl DnsProxy {
    /// 启动转发器。`on_match` 在命中白名单时被调用，并可返回一个确认通道：
    /// 转发器会等确认（最多 1.5 秒）后再把解析结果回给客户端——确保放行
    /// 规则先于客户端的首次连接建立，避免首个连接被拦掉。
    pub fn start<F>(upstream: Vec<IpAddr>, whitelist: Whitelist, on_match: F) -> Result<Self, String>
    where
        F: Fn(Resolved, std::sync::mpsc::Sender<()>) + Send + Sync + 'static,
    {
        if upstream.is_empty() {
            return Err("没有可用的上游 DNS 服务器".to_string());
        }

        let socket = UdpSocket::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 53))
            .map_err(|e| format!("监听 127.0.0.1:53 失败：{e}"))?;
        socket
            .set_read_timeout(Some(Duration::from_millis(500)))
            .map_err(|e| e.to_string())?;

        let running = Arc::new(AtomicBool::new(true));
        let flag = running.clone();
        let whitelist = Arc::new(whitelist);
        let on_match = Arc::new(on_match);

        std::thread::spawn(move || {
            let mut buf = [0u8; 4096];
            while flag.load(Ordering::Relaxed) {
                let (len, peer) = match socket.recv_from(&mut buf) {
                    Ok(v) => v,
                    Err(_) => continue, // 超时或取消
                };
                let query = &buf[..len];

                // 命中白名单的域名解析结果需要放行
                let question = question_name(query);
                let matched = question
                    .as_deref()
                    .map(|name| whitelist.matches(name))
                    .unwrap_or(false);

                // 原样转发给上游（逐个尝试，取第一个有响应的）
                let Some(response) = forward(query, &upstream) else {
                    continue;
                };

                if matched
                    && let Some(resolved) = parse_answers(&response)
                    && !resolved.addresses.is_empty()
                {
                    // 等主线程装好放行规则再回复客户端
                    let (ack_tx, ack_rx) = std::sync::mpsc::channel();
                    on_match(resolved, ack_tx);
                    let _ = ack_rx.recv_timeout(Duration::from_millis(1500));
                }

                let _ = socket.send_to(&response, peer);
            }
        });

        Ok(Self { running })
    }
}

/// 依次向上游服务器查询，返回第一个响应
fn forward(query: &[u8], upstream: &[IpAddr]) -> Option<Vec<u8>> {
    let bind_addr: SocketAddr = match upstream.first()? {
        IpAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        IpAddr::V6(_) => SocketAddr::new(IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED), 0),
    };
    let socket = UdpSocket::bind(bind_addr).ok()?;
    socket.set_read_timeout(Some(Duration::from_secs(3))).ok()?;

    let mut buf = [0u8; 4096];
    for server in upstream {
        let target = SocketAddr::new(*server, 53);
        if socket.send_to(query, target).is_err() {
            continue;
        }
        if let Ok((len, _)) = socket.recv_from(&mut buf) {
            return Some(buf[..len].to_vec());
        }
    }
    None
}

/// 读取查询里的域名（QNAME）
pub fn question_name(packet: &[u8]) -> Option<String> {
    if packet.len() < 12 {
        return None;
    }
    let qdcount = u16::from_be_bytes([packet[4], packet[5]]);
    if qdcount == 0 {
        return None;
    }
    read_name(packet, 12)
}

/// 解析响应里的 A/AAAA 记录
pub fn parse_answers(packet: &[u8]) -> Option<Resolved> {
    if packet.len() < 12 {
        return None;
    }
    let qdcount = u16::from_be_bytes([packet[4], packet[5]]) as usize;
    let ancount = u16::from_be_bytes([packet[6], packet[7]]) as usize;
    let mut offset = 12;

    // 跳过问题段
    for _ in 0..qdcount {
        let (_, next) = read_name_at(packet, offset)?;
        offset = next + 4; // QTYPE + QCLASS
    }

    let mut addresses = Vec::new();
    let mut ttl = u32::MAX;
    for _ in 0..ancount {
        let (_, next) = read_name_at(packet, offset)?;
        offset = next;
        if offset + 10 > packet.len() {
            return None;
        }
        let rtype = u16::from_be_bytes([packet[offset], packet[offset + 1]]);
        let record_ttl = u32::from_be_bytes([
            packet[offset + 4],
            packet[offset + 5],
            packet[offset + 6],
            packet[offset + 7],
        ]);
        let rdlength = u16::from_be_bytes([packet[offset + 8], packet[offset + 9]]) as usize;
        let rdata = offset + 10;
        if rdata + rdlength > packet.len() {
            return None;
        }
        match (rtype, rdlength) {
            (1, 4) => {
                addresses.push(IpAddr::V4(Ipv4Addr::new(
                    packet[rdata],
                    packet[rdata + 1],
                    packet[rdata + 2],
                    packet[rdata + 3],
                )));
                ttl = ttl.min(record_ttl);
            }
            (28, 16) => {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&packet[rdata..rdata + 16]);
                addresses.push(IpAddr::V6(std::net::Ipv6Addr::from(octets)));
                ttl = ttl.min(record_ttl);
            }
            _ => {}
        }
        offset = rdata + rdlength;
    }

    if addresses.is_empty() {
        None
    } else {
        Some(Resolved {
            addresses,
            ttl: ttl.clamp(30, 3600),
        })
    }
}

/// 从指定位置读取域名，返回 (名称, 名称之后的偏移)
fn read_name_at(packet: &[u8], start: usize) -> Option<(String, usize)> {
    let mut labels = Vec::new();
    let mut offset = start;
    let mut jumped = false;
    let mut end = start;
    let mut hops = 0;

    loop {
        if offset >= packet.len() || hops > 32 {
            return None;
        }
        let len = packet[offset] as usize;
        if len == 0 {
            if !jumped {
                end = offset + 1;
            }
            break;
        }
        // 压缩指针
        if len & 0xC0 == 0xC0 {
            if offset + 1 >= packet.len() {
                return None;
            }
            let pointer = ((len & 0x3F) << 8) | packet[offset + 1] as usize;
            if !jumped {
                end = offset + 2;
            }
            jumped = true;
            hops += 1;
            offset = pointer;
            continue;
        }
        if offset + 1 + len > packet.len() {
            return None;
        }
        labels.push(String::from_utf8_lossy(&packet[offset + 1..offset + 1 + len]).to_string());
        offset += 1 + len;
    }

    Some((labels.join("."), end))
}

fn read_name(packet: &[u8], start: usize) -> Option<String> {
    read_name_at(packet, start).map(|(name, _)| name)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 构造一个简单的响应包：example.com A 1.2.3.4
    fn build_response(name: &str, ip: [u8; 4]) -> Vec<u8> {
        let mut packet = vec![
            0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        ];
        for label in name.split('.') {
            packet.push(label.len() as u8);
            packet.extend_from_slice(label.as_bytes());
        }
        packet.push(0);
        packet.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // A / IN
        packet.extend_from_slice(&[0xC0, 0x0C]); // 指向问题名
        packet.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
        packet.extend_from_slice(&[0x00, 0x00, 0x00, 0x3C]); // TTL 60
        packet.extend_from_slice(&[0x00, 0x04]);
        packet.extend_from_slice(&ip);
        packet
    }

    #[test]
    fn parses_question_and_answer() {
        let packet = build_response("sub.example.com", [1, 2, 3, 4]);
        assert_eq!(question_name(&packet).as_deref(), Some("sub.example.com"));
        let resolved = parse_answers(&packet).expect("解析 A 记录");
        assert_eq!(
            resolved.addresses,
            vec![IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))]
        );
        assert_eq!(resolved.ttl, 60);
    }

    #[test]
    fn rejects_short_packet() {
        assert!(question_name(&[0u8; 4]).is_none());
        assert!(parse_answers(&[0u8; 4]).is_none());
    }

    /// 构造一个标准查询包（递归查询 A 记录）
    fn build_query(name: &str) -> Vec<u8> {
        let mut packet = vec![
            0xAB, 0xCD, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        for label in name.split('.') {
            packet.push(label.len() as u8);
            packet.extend_from_slice(label.as_bytes());
        }
        packet.push(0);
        packet.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // A / IN
        packet
    }

    /// 端到端：真实转发一次查询，并确认命中白名单时回调被触发。
    /// 默认忽略（依赖真实网络与上游 DNS），需要时用
    /// `cargo test -- --ignored forwards_real_query` 手动运行。
    #[test]
    #[ignore = "需要真实 DNS 上游与网络"]
    fn forwards_real_query() {
        use std::sync::{Arc, Mutex};

        let upstream: Vec<IpAddr> = std::env::var("NETCUT_TEST_DNS")
            .unwrap_or_else(|_| "192.168.100.254".to_string())
            .split(',')
            .filter_map(|s| s.trim().parse().ok())
            .collect();

        let hits = Arc::new(Mutex::new(Vec::new()));
        let recorder = hits.clone();
        let proxy = DnsProxy::start(
            upstream,
            Whitelist::parse("*.baidu.com"),
            move |resolved, ack| {
                recorder.lock().unwrap().extend(resolved.addresses.clone());
                let _ = ack.send(());
            },
        )
        .expect("启动转发器");

        let socket = UdpSocket::bind("127.0.0.1:0").expect("绑定客户端套接字");
        socket
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("设置超时");
        let query = build_query("www.baidu.com");
        socket
            .send_to(&query, "127.0.0.1:53")
            .expect("发送查询");

        let mut buf = [0u8; 4096];
        let (len, _) = socket.recv_from(&mut buf).expect("应收到上游响应");
        assert!(len > 12, "响应包过短：{len}");

        drop(proxy);
        let addresses = hits.lock().unwrap().clone();
        assert!(
            !addresses.is_empty(),
            "命中白名单的域名应触发放行回调（响应 {} 字节）",
            len
        );
    }
}
