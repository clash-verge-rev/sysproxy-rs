use crate::{Autoproxy, Error, Result, Sysproxy};
use log::debug;
use std::{borrow::Cow, process::Command, str::from_utf8};

impl Sysproxy {
    #[inline]
    pub fn get_system_proxy() -> Result<Sysproxy> {
        let service = default_network_service().or_else(|e| {
            debug!("Failed to get network service: {:?}", e);
            default_network_service_by_ns()
        });
        let service = match service {
            Ok(s) => s,
            Err(e) => {
                debug!("Failed to get network service by networksetup: {:?}", e);
                return Err(e);
            }
        };
        let service_owned = service;
        let service = service_owned.as_str();

        let mut socks = Sysproxy::get_socks(service)?;
        debug!("Getting SOCKS proxy: {:?}", socks);

        let http = Sysproxy::get_http(service)?;
        debug!("Getting HTTP proxy: {:?}", http);

        let https = Sysproxy::get_https(service)?;
        debug!("Getting HTTPS proxy: {:?}", https);

        let bypass = Sysproxy::get_bypass(service)?;
        debug!("Getting bypass domains: {:?}", bypass);

        socks.bypass = bypass;

        if !socks.enable {
            if http.enable {
                socks.enable = true;
                socks.host = http.host;
                socks.port = http.port;
            }
            if https.enable {
                socks.enable = true;
                socks.host = https.host;
                socks.port = https.port;
            }
        }

        Ok(socks)
    }

    #[inline]
    pub fn set_system_proxy(&self) -> Result<()> {
        let service = default_network_service().or_else(|e| {
            debug!("Failed to get network service: {:?}", e);
            default_network_service_by_ns()
        });
        let service = match service {
            Ok(s) => s,
            Err(e) => {
                debug!("Failed to get network service by networksetup: {:?}", e);
                return Err(e);
            }
        };
        let service_owned = service;
        let service = service_owned.as_str();

        debug!("Use network service: {}", service);

        debug!("Setting SOCKS proxy");
        self.set_socks(service)?;

        debug!("Setting HTTP proxy");
        self.set_https(service)?;

        debug!("Setting HTTPS proxy");
        self.set_http(service)?;

        debug!("Setting bypass domains");
        self.set_bypass(service)?;
        Ok(())
    }

    #[inline]
    pub fn get_http(service: &str) -> Result<Sysproxy> {
        get_proxy(ProxyType::Http, service)
    }

    #[inline]
    pub fn get_https(service: &str) -> Result<Sysproxy> {
        get_proxy(ProxyType::Https, service)
    }

    #[inline]
    pub fn get_socks(service: &str) -> Result<Sysproxy> {
        get_proxy(ProxyType::Socks, service)
    }

    #[inline]
    pub fn get_bypass(service: &str) -> Result<String> {
        let bypass_output = run_networksetup(&["-getproxybypassdomains", service])?;

        let bypass = bypass_output
            .split('\n')
            .filter(|s| !s.is_empty())
            .collect::<Vec<&str>>()
            .join(",");

        Ok(bypass)
    }

    #[inline]
    pub fn set_http(&self, service: &str) -> Result<()> {
        set_proxy(self, ProxyType::Http, service)
    }

    #[inline]
    pub fn set_https(&self, service: &str) -> Result<()> {
        set_proxy(self, ProxyType::Https, service)
    }

    #[inline]
    pub fn set_socks(&self, service: &str) -> Result<()> {
        set_proxy(self, ProxyType::Socks, service)
    }

    #[inline]
    pub fn set_bypass(&self, service: &str) -> Result<()> {
        set_bypass(self, service)
    }

    #[inline]
    pub fn has_permission() -> bool {
        let service = default_network_service().or_else(|e| {
            debug!("Failed to get network service: {:?}", e);
            default_network_service_by_ns()
        });
        let service = match service {
            Ok(s) => s,
            Err(e) => {
                debug!("Failed to get network service by networksetup: {:?}", e);
                return false;
            }
        };
        let service_owned = service;
        let service = service_owned.as_str();

        let result = run_networksetup(&["-setwebproxystate", service, "off"]);
        match result {
            Ok(_) => true,
            Err(e) => {
                debug!("Failed to check permission: {:?}", e);
                false
            }
        }
    }
}

impl Autoproxy {
    #[inline]
    pub fn get_auto_proxy() -> Result<Autoproxy> {
        let service = default_network_service().or_else(|e| {
            debug!("Failed to get network service: {:?}", e);
            default_network_service_by_ns()
        });
        let service = match service {
            Ok(s) => s,
            Err(e) => {
                debug!("Failed to get network service by networksetup: {:?}", e);
                return Err(e);
            }
        };
        let service_owned = service;
        let service = service_owned.as_str();

        let auto_output = run_networksetup(&["-getautoproxyurl", service])?;
        let auto = auto_output
            .trim()
            .split_once('\n')
            .ok_or_else(|| Error::ParseStr("auto".into()))?;
        let url = strip_str(auto.0.strip_prefix("URL: ").unwrap_or(""));
        let enable = auto.1 == "Enabled: Yes";

        Ok(Autoproxy {
            enable,
            url: url.to_string(),
        })
    }

    #[inline]
    pub fn set_auto_proxy(&self) -> Result<()> {
        let service = default_network_service().or_else(|e| {
            debug!("Failed to get network service: {:?}", e);
            default_network_service_by_ns()
        });
        let service = match service {
            Ok(s) => s,
            Err(e) => {
                debug!("Failed to get network service by networksetup: {:?}", e);
                return Err(e);
            }
        };
        let service_owned = service;
        let service = service_owned.as_str();

        let enable = if self.enable { "on" } else { "off" };
        let url = if self.url.is_empty() {
            "\"\""
        } else {
            &self.url
        };
        run_networksetup(&["-setautoproxyurl", service, url])?;
        run_networksetup(&["-setautoproxystate", service, enable])?;

        Ok(())
    }
}

#[derive(Debug)]
enum ProxyType {
    Http,
    Https,
    Socks,
}

impl ProxyType {
    #[inline]
    const fn as_str(&self) -> &'static str {
        match self {
            Self::Http => "webproxy",
            Self::Https => "securewebproxy",
            Self::Socks => "socksfirewallproxy",
        }
    }
}

impl std::fmt::Display for ProxyType {
    #[inline]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

#[inline]
fn run_networksetup<'a>(args: &[&str]) -> Result<Cow<'a, str>> {
    let mut command = Command::new("networksetup");
    let outoput = command.args(args);
    let output = outoput.output()?;
    let status = outoput.status()?;

    let stdout = from_utf8(&output.stdout).map_err(|_| Error::ParseStr("output".into()))?;

    if !status.success() {
        if stdout.contains("requires admin privileges") {
            log::error!(
                "Admin privileges required to run networksetup with args: {:?}, error: {}",
                args,
                stdout
            );
            return Err(Error::RequiresAdminPrivileges);
        }
    }

    Ok(Cow::Owned(stdout.to_string()))
}

#[inline]
fn set_proxy(proxy: &Sysproxy, proxy_type: ProxyType, service: &str) -> Result<()> {
    let target = format!("-set{}", proxy_type);
    let target = target.as_str();

    let host = proxy.host.as_str();
    let port = format!("{}", proxy.port);
    let port = port.as_str();

    run_networksetup(&[target, service, host, port])?;

    let target_state = format!("-set{}state", proxy_type);
    let enable = if proxy.enable { "on" } else { "off" };

    run_networksetup(&[target_state.as_str(), service, enable])?;

    Ok(())
}

#[inline]
fn set_bypass(proxy: &Sysproxy, service: &str) -> Result<()> {
    let domains = proxy.bypass.split(",").collect::<Vec<_>>();
    run_networksetup(&[["-setproxybypassdomains", service].to_vec(), domains].concat())?;
    Ok(())
}

#[inline]
fn get_proxy(proxy_type: ProxyType, service: &str) -> Result<Sysproxy> {
    let target = format!("-get{}", proxy_type);
    let target = target.as_str();

    let output = run_networksetup(&[target, service])?;

    let enable = parse(&output, "Enabled:");
    let enable = enable == "Yes";

    let host = parse(&output, "Server:");
    let host = host.into();

    let port = parse(&output, "Port:");
    let port = port.parse().map_err(|_| Error::ParseStr("port".into()))?;

    Ok(Sysproxy {
        enable,
        host,
        port,
        bypass: "".into(),
    })
}

#[inline]
fn parse<'a>(target: &'a str, key: &'a str) -> &'a str {
    match target.find(key) {
        Some(idx) => {
            let idx = idx + key.len();
            let value = &target[idx..];
            let value = match value.find("\n") {
                Some(end) => &value[..end],
                None => value,
            };
            value.trim()
        }
        None => "",
    }
}

#[inline]
fn strip_str(text: &str) -> &str {
    text.strip_prefix('"')
        .unwrap_or(text)
        .strip_suffix('"')
        .unwrap_or(text)
}

#[inline]
fn default_network_service() -> Result<String> {
    // 默认路由获取活跃接口
    if let Ok(service) = get_service_by_default_route() {
        debug!("Found service by default route: {}", service);
        return Ok(service);
    }

    // 检查常见的活跃网络服务
    if let Ok(service) = get_service_by_active_connection() {
        debug!("Found service by active connection: {}", service);
        return Ok(service);
    }

    debug!("All methods failed, falling back to default_network_service_by_ns");
    Err(Error::NetworkInterface)
}

#[inline]
fn get_service_by_default_route() -> Result<String> {
    let output = Command::new("route").args(["get", "default"]).output()?;

    let stdout = from_utf8(&output.stdout).map_err(|_| Error::ParseStr("route output".into()))?;
    let mut interface_name = None;

    for line in stdout.lines() {
        if line.trim().starts_with("interface:") {
            if let Some(v) = line.split(':').nth(1) {
                interface_name = Some(v.trim().to_string());
            }
            break;
        }
    }

    if let Some(interface) = interface_name {
        debug!("Default route interface: {}", interface);
        return get_server_by_order(interface);
    }

    Err(Error::NetworkInterface)
}

#[inline]
fn get_service_by_active_connection() -> Result<String> {
    // 动态获取网络服务
    let stdout = run_networksetup(&["-listallnetworkservices"])?;

    let services: Vec<&str> = stdout
        .split('\n')
        .skip(1) // 跳过提示行
        .filter(|s| !s.trim().is_empty() && !s.trim().starts_with('*')) // 过滤空行和禁用的服务
        .collect();

    for service in services {
        // 检查服务是否存在且有活跃连接
        let output = run_networksetup(&["-getinfo", service])?;

        if output.contains("** Error:") {
            return Err(Error::NetworkInterface);
        }

        // 检查是否有有效的IP地址
        for line in output.lines() {
            if line.starts_with("IP address:")
                && let Some(ip_raw) = line.split(':').nth(1)
            {
                let ip = ip_raw.trim();
                if !ip.is_empty() && ip != "none" {
                    debug!("Found active service with IP: {} - {}", service, ip);
                    return Ok(service.to_string());
                }
            }
        }
    }

    Err(Error::NetworkInterface)
}

#[inline]
fn default_network_service_by_ns() -> Result<String> {
    let stdout = run_networksetup(&["-listallnetworkservices"])?;
    let mut lines = stdout.split('\n');
    lines.next(); // ignore the tips

    // get the first service
    match lines.next() {
        Some(line) => Ok(line.into()),
        None => Err(Error::NetworkInterface),
    }
}

#[inline]
fn get_server_by_order(device: String) -> Result<String> {
    let services = listnetworkserviceorder()?;
    let service = services
        .into_iter()
        .find(|(_, _, d)| d == &device)
        .map(|(s, _, _)| s);
    match service {
        Some(service) => Ok(service),
        None => Err(Error::NetworkInterface),
    }
}

#[inline]
fn listnetworkserviceorder() -> Result<Vec<(String, String, String)>> {
    let stdout = run_networksetup(&["-listnetworkserviceorder"])?;

    let mut lines = stdout.split('\n');
    lines.next(); // ignore the tips

    let mut services = Vec::new();
    let mut p: Option<(String, String, String)> = None;

    for line in lines {
        if !line.starts_with("(") {
            continue;
        }

        if p.is_none() {
            if let Some(ri) = line.find(")") {
                let service = line[ri + 1..].trim();
                p = Some((service.into(), "".into(), "".into()));
            }
        } else {
            let line_inner = &line[1..line.len() - 1];
            if let (Some(pi), Some(di)) = (line_inner.find("Port:"), line_inner.find(", Device:")) {
                let port = line_inner[pi + 5..di].trim();
                let device = line_inner[di + 9..].trim();
                if let Some(p_val) = p.take() {
                    let (service, _, _) = p_val;
                    let new_p = (service, port.into(), device.into());
                    services.push(new_p);
                }
            }
        }
    }

    Ok(services)
}

#[allow(clippy::unwrap_used)]
#[test]
fn test_order() {
    let services = listnetworkserviceorder().unwrap();
    for (service, port, device) in services {
        println!("service: {}, port: {}, device: {}", service, port, device);
    }
}

#[test]
fn test_set_bypass() {
    let proxy = Sysproxy {
        host: "proxy.example.com".into(),
        port: 8080,
        enable: true,
        bypass: "no".into(),
    };
    let result = proxy.set_bypass("Wi-Fi");
    if let Err(e) = result {
        assert!(matches!(e, Error::RequiresAdminPrivileges));
        assert!(!Sysproxy::has_permission());
    }
}

#[allow(clippy::unwrap_used)]
#[test]
fn test_active_connection() {
    println!("Testing get_service_by_active_connection()...");
    match get_service_by_active_connection() {
        Ok(service) => {
            println!("✓ Found active service: '{}'", service);
            println!("  Service name length: {} bytes", service.len());
            println!("  Service name (debug): {:?}", service);
        }
        Err(e) => {
            println!("✗ Failed to get active service: {:?}", e);
        }
    }
}

#[allow(clippy::unwrap_used)]
#[test]
fn test_all_service_detection_methods() {
    println!("\n=== Testing All Service Detection Methods ===\n");

    println!("1. Testing get_service_by_default_route():");
    match get_service_by_default_route() {
        Ok(service) => println!("   ✓ Found: '{}' (len: {})", service, service.len()),
        Err(e) => println!("   ✗ Failed: {:?}", e),
    }

    println!("\n2. Testing get_service_by_active_connection():");
    match get_service_by_active_connection() {
        Ok(service) => println!("   ✓ Found: '{}' (len: {})", service, service.len()),
        Err(e) => println!("   ✗ Failed: {:?}", e),
    }

    println!("\n3. Testing default_network_service_by_ns():");
    match default_network_service_by_ns() {
        Ok(service) => println!("   ✓ Found: '{}' (len: {})", service, service.len()),
        Err(e) => println!("   ✗ Failed: {:?}", e),
    }

    println!("\n4. Testing default_network_service() (combined):");
    match default_network_service() {
        Ok(service) => println!("   ✓ Found: '{}' (len: {})", service, service.len()),
        Err(e) => println!("   ✗ Failed: {:?}", e),
    }
}
