use crate::{Autoproxy, Error, Result, Sysproxy};
use log::debug;
use std::{
    borrow::Cow,
    process::{Command, Stdio},
    str::from_utf8,
};
use system_configuration::{
    core_foundation::dictionary::CFDictionary, dynamic_store::SCDynamicStore,
    preferences::SCPreferences,
};
use system_configuration::{
    core_foundation::{array::CFArray, base::TCFType},
    network_configuration::SCNetworkService,
    sys::network_configuration::{
        SCNetworkProtocolGetConfiguration, SCNetworkServiceCopy, SCNetworkServiceCopyProtocol,
    },
    sys::preferences::{SCPreferencesLock, SCPreferencesUnlock},
};
use system_configuration::{
    core_foundation::{
        base::{CFRelease, CFType, ItemRef},
        number::CFNumber,
        string::CFString,
    },
    dynamic_store::SCDynamicStoreBuilder,
};

#[derive(Debug)]
enum ProxyType {
    Http,
    Https,
    Socks,
}

impl ProxyType {
    #[inline]
    const fn as_enable(&self) -> &'static str {
        match self {
            Self::Http => "HTTPEnable",
            Self::Https => "HTTPSEnable",
            Self::Socks => "SOCKSEnable",
        }
    }
    #[inline]
    const fn as_host(&self) -> &'static str {
        match self {
            Self::Http => "HTTPProxy",
            Self::Https => "HTTPSProxy",
            Self::Socks => "SOCKSProxy",
        }
    }
    #[inline]
    const fn as_port(&self) -> &'static str {
        match self {
            Self::Http => "HTTPPort",
            Self::Https => "HTTPSPort",
            Self::Socks => "SOCKSPort",
        }
    }
}

impl ProxyType {
    #[inline]
    const fn as_set_str(&self) -> &'static str {
        match self {
            Self::Http => "-setwebproxy",
            Self::Https => "-setsecurewebproxy",
            Self::Socks => "-setsocksfirewallproxy",
        }
    }
    #[inline]
    const fn as_state_cmd(&self) -> &'static str {
        match self {
            Self::Http => "-setwebproxystate",
            Self::Https => "-setsecurewebproxystate",
            Self::Socks => "-setsocksfirewallproxystate",
        }
    }
}

impl Sysproxy {
    #[inline]
    pub fn get_system_proxy() -> Result<Sysproxy> {
        let service_uuid = get_active_network_service_uuid()?;
        let scp = SCPreferences::default(&CFString::new("sysproxy-rs"));
        let proxies_dict = get_proxies_by_service_uuid(&scp, &service_uuid)?;

        let mut socks = parse_proxies_from_dict(&proxies_dict, ProxyType::Socks)?;
        debug!("Getting SOCKS proxy: {:?}", socks);

        let http = parse_proxies_from_dict(&proxies_dict, ProxyType::Http)?;
        debug!("Getting HTTP proxy: {:?}", http);

        let https = parse_proxies_from_dict(&proxies_dict, ProxyType::Https)?;
        debug!("Getting HTTPS proxy: {:?}", https);

        let bypass = parse_bypass_from_dict(&proxies_dict)?.join(",");
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
        let service = get_active_network_service()?;
        let service = service.to_string();
        let service = service.as_str();

        debug!("Use network service: {}", service);

        debug!("Setting SOCKS proxy");
        self.set_socks(service)?;

        debug!("Setting HTTPS proxy");
        self.set_https(service)?;

        debug!("Setting HTTP proxy");
        self.set_http(service)?;

        debug!("Setting bypass domains");
        self.set_bypass(service)?;
        Ok(())
    }

    #[inline]
    pub fn get_http(
        service: &CFString,
        cfd: Option<&CFDictionary<CFString, CFType>>,
    ) -> Result<Sysproxy> {
        let cfd = match cfd {
            Some(s) => s,
            None => &get_proxies_dict_from_service_uuid(service)?,
        };
        parse_proxies_from_dict(cfd, ProxyType::Http)
    }

    #[inline]
    pub fn get_https(
        service: &CFString,
        cfd: Option<&CFDictionary<CFString, CFType>>,
    ) -> Result<Sysproxy> {
        let cfd = match cfd {
            Some(s) => s,
            None => &get_proxies_dict_from_service_uuid(service)?,
        };
        parse_proxies_from_dict(cfd, ProxyType::Https)
    }

    #[inline]
    pub fn get_socks(
        service: &CFString,
        cfd: Option<&CFDictionary<CFString, CFType>>,
    ) -> Result<Sysproxy> {
        let cfd = match cfd {
            Some(s) => s,
            None => &get_proxies_dict_from_service_uuid(service)?,
        };
        parse_proxies_from_dict(cfd, ProxyType::Socks)
    }

    #[inline]
    pub fn get_bypass(
        service: &CFString,
        cfd: Option<&CFDictionary<CFString, CFType>>,
    ) -> Result<String> {
        let cfd = match cfd {
            Some(s) => s,
            None => &get_proxies_dict_from_service_uuid(service)?,
        };
        let bypass_list = parse_bypass_from_dict(cfd)?;
        Ok(bypass_list.join(","))
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
        let scp = SCPreferences::default(&CFString::new("sysproxy-rs"));
        unsafe {
            let locked = SCPreferencesLock(scp.as_concrete_TypeRef(), 0);
            if locked != 0 {
                SCPreferencesUnlock(scp.as_concrete_TypeRef());
                true
            } else {
                debug!("Permission check failed: SCPreferencesLock returned false");
                false
            }
        }
    }
}

impl Autoproxy {
    #[inline]
    pub fn get_auto_proxy() -> Result<Autoproxy> {
        let service = get_active_network_service_uuid()?;
        let store = SCDynamicStoreBuilder::new("sysproxy-rs")
            .build()
            .ok_or(Error::SCDynamicStore)?;
        get_autoproxies_by_service_uuid(&store, &service)
    }

    #[inline]
    pub fn set_auto_proxy(&self) -> Result<()> {
        let service = get_active_network_service()?.to_string();
        let service = service.as_str();
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

#[inline]
fn run_networksetup<'a>(args: &[&str]) -> Result<Cow<'a, str>> {
    let output = Command::new("networksetup")
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()?;

    let stdout = from_utf8(&output.stdout).map_err(|_| Error::ParseStr("output".into()))?;

    if !output.status.success() {
        if stdout.contains("requires admin privileges") {
            log::error!(
                "Admin privileges required to run networksetup with args: {:?}, error: {}",
                args,
                stdout
            );
            return Err(Error::RequiresAdminPrivileges);
        }
        log::error!("networksetup failed with args: {:?}, output: {}", args, stdout);
        return Err(Error::ParseStr(format!("networksetup failed: {}", stdout.trim())));
    }

    Ok(Cow::Owned(stdout.to_string()))
}

#[inline]
fn set_proxy(proxy: &Sysproxy, proxy_type: ProxyType, service: &str) -> Result<()> {
    let host = proxy.host.as_str();
    let port = format!("{}", proxy.port);
    let port = port.as_str();

    run_networksetup(&[proxy_type.as_set_str(), service, host, port])?;

    let enable = if proxy.enable { "on" } else { "off" };

    run_networksetup(&[proxy_type.as_state_cmd(), service, enable])?;

    Ok(())
}

#[inline]
fn set_bypass(proxy: &Sysproxy, service: &str) -> Result<()> {
    let mut args = vec!["-setproxybypassdomains", service];
    let domains: Vec<&str> = if proxy.bypass.is_empty() {
        Vec::new()
    } else {
        proxy.bypass.split(",").collect()
    };
    args.extend(&domains);
    run_networksetup(&args)?;
    Ok(())
}

fn get_active_network_service() -> Result<CFString> {
    // `networksetup` identifies a connection by its *service* name (the
    // user-visible name in Network preferences, e.g. "Wi-Fi" or "internet1"),
    // not by the interface/hardware-port display name. They only coincide by
    // luck (Wi-Fi), so a wired service named differently from its port (USB
    // ethernet, renamed services) would be addressed by the wrong identifier.
    // The service name is the `UserDefinedName` stored under the service's
    // dynamic-store entry.
    let service_uuid = get_active_network_service_uuid()?;
    let store = SCDynamicStoreBuilder::new("sysproxy-rs")
        .build()
        .ok_or(Error::SCDynamicStore)?;
    let key = CFString::new(&format!("Setup:/Network/Service/{service_uuid}"));
    let dict = store
        .get(key)
        .and_then(|v| v.downcast_into::<CFDictionary>())
        .ok_or(Error::NetworkInterface)?;
    let name_key = CFString::from_static_string("UserDefinedName");
    let val_ptr = dict
        .find(name_key.as_CFTypeRef() as *const _)
        .ok_or(Error::NetworkInterface)?;
    let name = unsafe { CFString::wrap_under_get_rule(*val_ptr as _) };
    Ok(name)
}

fn get_active_network_service_uuid() -> Result<CFString> {
    let store = SCDynamicStoreBuilder::new("sysproxy-rs")
        .build()
        .ok_or(Error::SCDynamicStore)?;
    let global_ipv4_key = CFString::from_static_string("State:/Network/Global/IPv4");
    let sets = store.get(global_ipv4_key).ok_or(Error::SCDynamicStore)?;
    if let Some(dict) = sets.downcast_into::<CFDictionary>() {
        let key = CFString::from_static_string("PrimaryService");
        let val_ptr = dict.find(key.as_CFTypeRef() as *const _);
        if let Some(ptr) = val_ptr {
            let service_id_cf = unsafe { CFString::wrap_under_get_rule(*ptr as _) };
            return Ok(service_id_cf);
        }
    }
    Err(Error::NetworkInterface)
}

fn parse_proxies_from_dict(
    cfd: &CFDictionary<CFString, CFType>,
    proxy_type: ProxyType,
) -> Result<Sysproxy> {
    let enable = read_bool_flag(cfd, proxy_type.as_enable());
    let port = read_port(cfd, proxy_type.as_port());
    let host = read_host(cfd, proxy_type.as_host());
    let enable = enable && !host.is_empty() && port != 0;

    Ok(Sysproxy {
        enable,
        host,
        port,
        bypass: String::new(),
    })
}

fn parse_proxyauto_from_dict(cfd: &CFDictionary<CFString, CFType>) -> Result<Autoproxy> {
    let enable = get_proxy_value(cfd, "ProxyAutoConfigEnable")
        .and_then(|x| x.downcast::<CFNumber>())
        .and_then(|num| num.to_i32())
        .map(|v| v != 0)
        .unwrap_or(false);
    let url = get_proxy_value(cfd, "ProxyAutoConfigURLString")
        .and_then(|x| x.downcast::<CFString>().map(|s| s.to_string()))
        .unwrap_or_default();

    let url = if url == "\"\"" { String::new() } else { url };
    let enable = enable && !url.is_empty();

    Ok(Autoproxy { enable, url })
}

fn parse_bypass_from_dict(cfd: &CFDictionary<CFString, CFType>) -> Result<Vec<String>> {
    let Some(bypass_list_raw) =
        get_proxy_value(cfd, "ExceptionsList").and_then(|x| x.downcast::<CFArray>())
    else {
        return Ok(Vec::new());
    };

    let mut bypass_list = Vec::with_capacity(bypass_list_raw.len() as usize);
    for bypass_raw in &bypass_list_raw {
        let cf_type: CFType = unsafe { TCFType::wrap_under_get_rule(*bypass_raw as _) };
        if let Some(cf_string) = cf_type.downcast::<CFString>() {
            bypass_list.push(cf_string.to_string());
        }
    }

    Ok(bypass_list)
}

fn get_proxy_value<'a>(
    dict: &'a CFDictionary<CFString, CFType>,
    key: &'static str,
) -> Option<ItemRef<'a, CFType>> {
    let cf_key = CFString::from_static_string(key);
    dict.find(&cf_key)
}

fn read_bool_flag(cfd: &CFDictionary<CFString, CFType>, key: &'static str) -> bool {
    get_proxy_value(cfd, key)
        .and_then(|x| x.downcast::<CFNumber>())
        .and_then(|num| num.to_i32())
        .is_some_and(|v| v != 0)
}

fn read_port(cfd: &CFDictionary<CFString, CFType>, key: &'static str) -> u16 {
    get_proxy_value(cfd, key)
        .and_then(|x| x.downcast::<CFNumber>())
        .and_then(|num| num.to_i32())
        .filter(|v| (0..=u16::MAX as i32).contains(v))
        .map_or(0, |v| v as u16)
}

fn read_host(cfd: &CFDictionary<CFString, CFType>, key: &'static str) -> String {
    get_proxy_value(cfd, key)
        .and_then(|x| x.downcast::<CFString>().map(|s| s.to_string()))
        .unwrap_or_default()
}

// #[allow(dead_code)]
// fn get_service_id_by_bsd_name(scp: &SCPreferences, bsd_name: &str) -> Option<CFString> {
//     let services = SCNetworkService::get_services(scp);
//     for service in &services {
//         if let Some(interface) = service
//             .network_interface()
//             .and_then(|scn_inter| scn_inter.bsd_name().map(|name| name.to_string()))
//         {
//             if interface == bsd_name {
//                 return service.id();
//             }
//         }
//     }
//     None
// }

fn get_service_id_by_display_name(scp: &SCPreferences, name: &CFString) -> Option<CFString> {
    let services = SCNetworkService::get_services(scp);
    for service in &services {
        if let Some(interface) = service
            .network_interface()
            .and_then(|scn_inter| scn_inter.display_name())
            && interface == *name
        {
            return service.id();
        }
    }
    None
}

fn get_autoproxies_by_service_uuid(
    store: &SCDynamicStore,
    service_uuid: &CFString,
) -> Result<Autoproxy> {
    let proxy_key = CFString::new(&format!("Setup:/Network/Service/{}/Proxies", service_uuid));

    let proxies_cf_type = store
        .get(proxy_key)
        .ok_or_else(|| Error::ParseStr("Proxy settings not found in DynamicStore".into()))?;

    let proxies_dict_raw = proxies_cf_type
        .downcast_into::<CFDictionary>()
        .ok_or_else(|| Error::ParseStr("Not a dictionary".into()))?;

    let proxies_dict: CFDictionary<CFString, CFType> =
        unsafe { CFDictionary::wrap_under_get_rule(proxies_dict_raw.as_concrete_TypeRef() as _) };

    parse_proxyauto_from_dict(&proxies_dict)
}

fn get_proxies_by_service_uuid(
    scp: &SCPreferences,
    service_uuid: &CFString,
) -> Result<CFDictionary<CFString, CFType>> {
    unsafe {
        let service_ref = SCNetworkServiceCopy(
            scp.as_concrete_TypeRef(),
            service_uuid.as_concrete_TypeRef(),
        );
        if service_ref.is_null() {
            return Err(Error::SCPreferences);
        }

        let protocol_ref = SCNetworkServiceCopyProtocol(
            service_ref,
            CFString::from_static_string("Proxies").as_concrete_TypeRef(),
        );
        if protocol_ref.is_null() {
            CFRelease(service_ref);
            return Err(Error::SCPreferences);
        }

        let config = SCNetworkProtocolGetConfiguration(protocol_ref);
        if config.is_null() {
            CFRelease(service_ref);
            CFRelease(protocol_ref);
            return Err(Error::SCPreferences);
        }

        let dict: CFDictionary<CFString, CFType> = CFDictionary::wrap_under_get_rule(config as _);

        CFRelease(service_ref);
        CFRelease(protocol_ref);

        Ok(dict)
    }
}

pub fn get_proxies_dict_from_service_uuid(
    service: &CFString,
) -> Result<CFDictionary<CFString, CFType>> {
    let scp = SCPreferences::default(&CFString::new("sysproxy-rs"));
    let service_uuid =
        get_service_id_by_display_name(&scp, service).ok_or(Error::NetworkInterface)?;
    get_proxies_by_service_uuid(&scp, &service_uuid)
}

#[test]
#[allow(clippy::unwrap_used)]
fn test_get_service_id_by_display_name() {
    let scp = SCPreferences::default(&CFString::new("sysproxy-rs"));
    let display_name = CFString::new("Wi-Fi");
    let service_uuid = get_service_id_by_display_name(&scp, &display_name).unwrap();
    assert!(!service_uuid.to_string().is_empty());
    println!("service_uuid: {:?}", service_uuid);
    let proxies = get_proxies_by_service_uuid(&scp, &service_uuid).unwrap();
    assert!(!proxies.is_empty());
    println!("proxies: {:?}", proxies);
}

#[test]
fn active_service_name_is_recognized_by_networksetup() {
    // Regression: get_active_network_service must return the *service* name
    // that `networksetup` understands, not the interface display name. They
    // differ for e.g. USB ethernet adapters or renamed services, which broke
    // system-proxy toggling on wired connections.
    let Ok(service) = get_active_network_service() else {
        return; // no active network service in this environment
    };
    let service = service.to_string();

    let Ok(output) = Command::new("networksetup")
        .arg("-listallnetworkservices")
        .output()
    else {
        return;
    };
    let listing = String::from_utf8_lossy(&output.stdout);
    let known = listing
        .lines()
        .skip(1) // first line is a human-readable header
        .map(|l| l.trim_start_matches('*').trim())
        .any(|name| name == service);

    assert!(
        known,
        "active service {service:?} not recognized by networksetup:\n{listing}"
    );
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

#[test]
fn parse_proxy_missing_fields_disable_proxy() {
    let dict = CFDictionary::from_CFType_pairs(&[(
        CFString::from_static_string("HTTPEnable"),
        CFNumber::from(1).as_CFType(),
    )]);
    let proxy = parse_proxies_from_dict(&dict, ProxyType::Http).unwrap();
    assert!(!proxy.enable);
    assert_eq!(proxy.host, "");
    assert_eq!(proxy.port, 0);
}

#[test]
fn parse_proxy_negative_port_zeroed() {
    let dict = CFDictionary::from_CFType_pairs(&[
        (
            CFString::from_static_string("HTTPEnable"),
            CFNumber::from(1).as_CFType(),
        ),
        (
            CFString::from_static_string("HTTPProxy"),
            CFString::from_static_string("localhost").as_CFType(),
        ),
        (
            CFString::from_static_string("HTTPPort"),
            CFNumber::from(-1).as_CFType(),
        ),
    ]);
    let proxy = parse_proxies_from_dict(&dict, ProxyType::Http).unwrap();
    assert!(!proxy.enable);
    assert_eq!(proxy.port, 0);
}

#[test]
fn parse_proxy_too_large_port_zeroed() {
    let dict = CFDictionary::from_CFType_pairs(&[
        (
            CFString::from_static_string("HTTPEnable"),
            CFNumber::from(1).as_CFType(),
        ),
        (
            CFString::from_static_string("HTTPProxy"),
            CFString::from_static_string("localhost").as_CFType(),
        ),
        (
            CFString::from_static_string("HTTPPort"),
            CFNumber::from(i32::MAX).as_CFType(),
        ),
    ]);
    let proxy = parse_proxies_from_dict(&dict, ProxyType::Http).unwrap();
    assert!(!proxy.enable);
    assert_eq!(proxy.port, 0);
}

#[test]
fn parse_bypass_missing_returns_empty() {
    let dict: CFDictionary<CFString, CFType> = CFDictionary::from_CFType_pairs(&[]);
    let bypass = parse_bypass_from_dict(&dict).unwrap();
    assert!(bypass.is_empty());
}

#[test]
fn parse_proxyauto_defaults_to_false_and_empty_url() {
    let dict: CFDictionary<CFString, CFType> = CFDictionary::from_CFType_pairs(&[]);
    let auto = parse_proxyauto_from_dict(&dict).unwrap();
    assert!(!auto.enable);
    assert_eq!(auto.url, "");
}

#[test]
fn parse_proxyauto_disable_when_url_missing() {
    let dict = CFDictionary::from_CFType_pairs(&[(
        CFString::from_static_string("ProxyAutoConfigEnable"),
        CFNumber::from(1).as_CFType(),
    )]);
    let auto = parse_proxyauto_from_dict(&dict).unwrap();
    assert!(!auto.enable);
    assert_eq!(auto.url, "");
}
