mod network;

pub use network::NetworkServiceMonitor;

use crate::{Autoproxy, Error, ProxyEndpoint, ProxySnapshot, Result, Sysproxy, WriteProgress};
use log::debug;
use std::ffi::c_int;
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};
use system_configuration::core_foundation::dictionary::CFMutableDictionary;
use system_configuration::sys::{
    network_configuration::{SCNetworkProtocolRef, SCNetworkProtocolSetConfiguration},
    preferences::{SCPreferencesApplyChanges, SCPreferencesCommitChanges},
};
use system_configuration::{core_foundation::dictionary::CFDictionary, preferences::SCPreferences};
use system_configuration::{
    core_foundation::{array::CFArray, base::TCFType},
    network_configuration::{SCNetworkService, SCNetworkSet},
    sys::network_configuration::{
        SCNetworkProtocolGetConfiguration, SCNetworkServiceCopy, SCNetworkServiceCopyProtocol,
        SCNetworkServiceGetEnabled, SCNetworkServiceGetName, SCNetworkServiceRef,
        SCNetworkSetCopyCurrent, SCNetworkSetCopyServices,
    },
    sys::preferences::{SCPreferencesLock, SCPreferencesUnlock},
};
use system_configuration::{
    core_foundation::{
        base::{CFRelease, CFType, ItemRef},
        number::CFNumber,
        string::{CFString, CFStringRef},
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
    /// Whether an active network service is available for proxy writes.
    pub fn has_network_service() -> Result<bool> {
        match get_active_network_service() {
            Ok(_) => Ok(true),
            Err(Error::NoActiveNetworkService | Error::NetworkInterface) => Ok(false),
            Err(error) => Err(error),
        }
    }

    #[inline]
    pub fn get_system_proxy() -> Result<Sysproxy> {
        let scp = SCPreferences::default(&CFString::new("sysproxy-rs"));
        let service_uuid = get_active_network_service_uuid(&scp)?;
        let proxies_dict = resolve_proxies_dict(&scp, &service_uuid)?;

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

    /// Read every protocol separately, plus PAC and the bypass list.
    ///
    /// All fields come from one resolved dictionary for a consistent snapshot.
    #[inline]
    pub fn snapshot() -> Result<ProxySnapshot> {
        let scp = SCPreferences::default(&CFString::new("sysproxy-rs"));
        let service_uuid = get_active_network_service_uuid(&scp)?;
        let proxies_dict = resolve_proxies_dict(&scp, &service_uuid)?;

        let endpoint = |proxy_type: ProxyType| -> Result<ProxyEndpoint> {
            let switched_on = read_bool_flag(&proxies_dict, proxy_type.as_enable());
            let parsed = parse_proxies_from_dict(&proxies_dict, proxy_type)?;
            Ok(ProxyEndpoint {
                host: parsed.host,
                port: parsed.port,
                enable: parsed.enable,
                switched_on,
            })
        };
        Ok(ProxySnapshot {
            socks: endpoint(ProxyType::Socks)?,
            http: endpoint(ProxyType::Http)?,
            https: endpoint(ProxyType::Https)?,
            auto: parse_proxyauto_from_dict(&proxies_dict)?,
            auto_switched_on: read_bool_flag(&proxies_dict, "ProxyAutoConfigEnable"),
            bypass: parse_bypass_from_dict(&proxies_dict)?.join(","),
        })
    }

    #[inline]
    pub fn set_system_proxy(&self) -> Result<()> {
        let service = get_active_network_service()?;
        let service = service.to_string();
        let service = service.as_str();

        debug!("Use network service: {}", service);

        // Keep one progress counter across all protocol writes.
        let mut writes = WriteSequence::new(SYSTEM_PROXY_WRITES);

        debug!("Setting SOCKS proxy");
        set_proxy(&mut writes, self, ProxyType::Socks, service)?;

        debug!("Setting HTTPS proxy");
        set_proxy(&mut writes, self, ProxyType::Https, service)?;

        debug!("Setting HTTP proxy");
        set_proxy(&mut writes, self, ProxyType::Http, service)?;

        debug!("Setting bypass domains");
        set_bypass(&mut writes, self, service)?;
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
        set_proxy(
            &mut WriteSequence::new(WRITES_PER_PROXY_TYPE),
            self,
            ProxyType::Http,
            service,
        )
    }

    #[inline]
    pub fn set_https(&self, service: &str) -> Result<()> {
        set_proxy(
            &mut WriteSequence::new(WRITES_PER_PROXY_TYPE),
            self,
            ProxyType::Https,
            service,
        )
    }

    #[inline]
    pub fn set_socks(&self, service: &str) -> Result<()> {
        set_proxy(
            &mut WriteSequence::new(WRITES_PER_PROXY_TYPE),
            self,
            ProxyType::Socks,
            service,
        )
    }

    #[inline]
    pub fn set_bypass(&self, service: &str) -> Result<()> {
        set_bypass(&mut WriteSequence::new(BYPASS_WRITES), self, service)
    }

    /// Try to lock `SCPreferences` without waiting.
    ///
    /// This does not predict whether authorized `networksetup` writes will succeed.
    #[inline]
    pub fn can_lock_scpreferences() -> bool {
        let scp = SCPreferences::default(&CFString::new("sysproxy-rs"));
        unsafe {
            let locked = SCPreferencesLock(scp.as_concrete_TypeRef(), 0);
            if locked != 0 {
                SCPreferencesUnlock(scp.as_concrete_TypeRef());
                true
            } else {
                debug!(
                    "SCPreferencesLock returned false; this says nothing about write permission"
                );
                false
            }
        }
    }
}

impl Autoproxy {
    #[inline]
    /// Read PAC settings from the resolved service dictionary.
    pub fn get_auto_proxy() -> Result<Autoproxy> {
        let scp = SCPreferences::default(&CFString::new("sysproxy-rs"));
        let service_uuid = get_active_network_service_uuid(&scp)?;
        let proxies_dict = resolve_proxies_dict(&scp, &service_uuid)?;
        parse_proxyauto_from_dict(&proxies_dict)
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
        let mut writes = WriteSequence::new(AUTO_PROXY_WRITES);
        writes.run(&["-setautoproxyurl", service, url])?;
        writes.run(&["-setautoproxystate", service, enable])?;

        Ok(())
    }
}

type ManagedProxyFields = Vec<Option<Vec<u8>>>;

fn managed_proxy_fields(dict: &CFDictionary<CFString, CFType>) -> Result<ManagedProxyFields> {
    use system_configuration::core_foundation::propertylist::{
        create_data, kCFPropertyListBinaryFormat_v1_0,
    };
    const KEYS: [&str; 12] = [
        "HTTPProxy",
        "HTTPPort",
        "HTTPEnable",
        "HTTPSProxy",
        "HTTPSPort",
        "HTTPSEnable",
        "SOCKSProxy",
        "SOCKSPort",
        "SOCKSEnable",
        "ProxyAutoConfigURLString",
        "ProxyAutoConfigEnable",
        "ExceptionsList",
    ];
    KEYS.iter()
        .map(|key| {
            dict.find(CFString::from_static_string(key))
                .map(|value| {
                    create_data(value.as_CFTypeRef(), kCFPropertyListBinaryFormat_v1_0)
                        .map(|data| data.bytes().to_vec())
                        .map_err(|_| Error::SystemConfiguration("capture managed proxy field"))
                })
                .transpose()
        })
        .collect()
}

/// Bounded, because a privileged service must not wait indefinitely behind another writer.
const PREFERENCES_LOCK_TIMEOUT: Duration = Duration::from_secs(2);
const PREFERENCES_LOCK_RETRY: Duration = Duration::from_millis(20);
/// `kSCStatusPrefsBusy`: another writer, such as `networksetup`, holds the lock.
const SC_STATUS_PREFS_BUSY: c_int = 3002;

#[link(name = "SystemConfiguration", kind = "framework")]
unsafe extern "C" {
    fn SCError() -> c_int;
}

fn lock_preferences(preferences: &SCPreferences) -> Result<()> {
    let deadline = Instant::now() + PREFERENCES_LOCK_TIMEOUT;
    loop {
        if unsafe { SCPreferencesLock(preferences.as_concrete_TypeRef(), 0) } != 0 {
            return Ok(());
        }
        let status = unsafe { SCError() };
        if status != SC_STATUS_PREFS_BUSY || Instant::now() >= deadline {
            return Err(Error::PreferencesLock(status));
        }
        std::thread::sleep(PREFERENCES_LOCK_RETRY);
    }
}

struct NativeProxyWriter {
    preferences: SCPreferences,
    protocol: SCNetworkProtocolRef,
    config: CFMutableDictionary<CFString, CFType>,
    locked: bool,
    service_id: String,
}

impl NativeProxyWriter {
    fn open() -> Result<Self> {
        Self::open_service(None)
    }

    fn open_service(service_id: Option<&str>) -> Result<Self> {
        let primary = if service_id.is_none() {
            Some(read_primary_ipv4()?)
        } else {
            None
        };
        let preferences = SCPreferences::default(&CFString::new("sysproxy-rs privileged native"));
        // Resolve only after locking: a session that read the preferences before locking fails
        // the lock as stale when they changed in between.
        lock_preferences(&preferences)?;

        unsafe {
            let selected = match (service_id, primary.as_ref()) {
                (Some(id), _) => Ok(CFString::new(id)),
                (None, Some(primary)) => resolve_active_service(&preferences, primary),
                (None, None) => Err(Error::NoActiveNetworkService),
            };
            let (service_id, service) = match selected.and_then(|id| {
                copy_network_service(&preferences, &id).map(|service| (id.to_string(), service))
            }) {
                Ok(service) => service,
                Err(error) => {
                    SCPreferencesUnlock(preferences.as_concrete_TypeRef());
                    return Err(error);
                }
            };

            let protocol = SCNetworkServiceCopyProtocol(
                service,
                CFString::from_static_string("Proxies").as_concrete_TypeRef(),
            );
            CFRelease(service.cast());
            if protocol.is_null() {
                SCPreferencesUnlock(preferences.as_concrete_TypeRef());
                return Err(Error::SystemConfiguration("resolve proxy protocol"));
            }

            let current = SCNetworkProtocolGetConfiguration(protocol);
            let config = if current.is_null() {
                CFMutableDictionary::new()
            } else {
                let current = CFDictionary::<CFString, CFType>::wrap_under_get_rule(current);
                CFMutableDictionary::from(&current)
            };

            Ok(Self {
                preferences,
                protocol,
                config,
                locked: true,
                service_id,
            })
        }
    }

    fn set_number(&mut self, key: &'static str, value: i32) {
        self.config.set(
            CFString::from_static_string(key),
            CFNumber::from(value).as_CFType(),
        );
    }

    fn set_string(&mut self, key: &'static str, value: &str) {
        self.config.set(
            CFString::from_static_string(key),
            CFString::new(value).as_CFType(),
        );
    }

    fn set_global(&mut self, host: &str, port: u16, bypass: &str, enable: bool) {
        const PROXY_KEYS: [(&str, &str, &str); 3] = [
            ("HTTPProxy", "HTTPPort", "HTTPEnable"),
            ("HTTPSProxy", "HTTPSPort", "HTTPSEnable"),
            ("SOCKSProxy", "SOCKSPort", "SOCKSEnable"),
        ];

        for (host_key, port_key, enable_key) in PROXY_KEYS {
            self.set_string(host_key, host);
            self.set_number(port_key, i32::from(port));
            self.set_number(enable_key, i32::from(enable));
        }

        let bypass = if bypass.is_empty() {
            Vec::new()
        } else {
            bypass.split(',').map(CFString::new).collect()
        };
        self.config.set(
            CFString::from_static_string("ExceptionsList"),
            CFArray::from_CFTypes(&bypass).as_CFType(),
        );
    }

    fn set_pac(&mut self, url: &str, enable: bool) {
        self.set_string("ProxyAutoConfigURLString", url);
        self.set_number("ProxyAutoConfigEnable", i32::from(enable));
    }

    fn receipt(&self) -> Result<PrivilegedProxyReceipt> {
        Ok(PrivilegedProxyReceipt {
            service_id: self.service_id.clone(),
            states: vec![managed_proxy_fields(&self.config.to_immutable())?],
        })
    }

    fn commit(&mut self) -> Result<()> {
        let config = self.config.to_immutable();
        if unsafe { SCNetworkProtocolSetConfiguration(self.protocol, config.as_concrete_TypeRef()) }
            == 0
        {
            return Err(Error::SystemConfiguration("stage proxy configuration"));
        }
        if unsafe { SCPreferencesCommitChanges(self.preferences.as_concrete_TypeRef()) } == 0 {
            return Err(Error::SystemConfiguration("commit proxy configuration"));
        }
        if unsafe { SCPreferencesApplyChanges(self.preferences.as_concrete_TypeRef()) } == 0 {
            return Err(Error::SystemConfiguration("apply proxy configuration"));
        }
        Ok(())
    }

    fn finish(mut self) -> Result<()> {
        if self.unlock() {
            Ok(())
        } else {
            Err(Error::SystemConfiguration("unlock preferences"))
        }
    }

    fn unlock(&mut self) -> bool {
        if !self.locked {
            return true;
        }
        let unlocked = unsafe { SCPreferencesUnlock(self.preferences.as_concrete_TypeRef()) != 0 };
        if unlocked {
            self.locked = false;
        }
        unlocked
    }
}

impl Drop for NativeProxyWriter {
    fn drop(&mut self) {
        if self.locked {
            self.unlock();
        }
        unsafe {
            CFRelease(self.protocol.cast());
        }
    }
}

pub(crate) fn apply_privileged_native(system: &Sysproxy, auto: &Autoproxy) -> Result<()> {
    let mut writer = NativeProxyWriter::open()?;
    writer.set_global(&system.host, system.port, &system.bypass, system.enable);
    writer.set_pac(&auto.url, auto.enable);
    writer.commit()?;
    writer.finish()
}

/// Identifies the exact service and proxy fields written by one native operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrivilegedProxyReceipt {
    service_id: String,
    states: Vec<ManagedProxyFields>,
}

/// A receipt is retained even when committing, applying or unlocking fails after a possible write.
#[derive(Debug)]
pub struct PrivilegedProxyApply {
    pub receipt: PrivilegedProxyReceipt,
    pub result: Result<()>,
}

pub(crate) fn apply_privileged_native_owned(
    system: &Sysproxy,
    auto: &Autoproxy,
) -> Result<PrivilegedProxyApply> {
    let mut writer = NativeProxyWriter::open()?;
    writer.set_global(&system.host, system.port, &system.bypass, system.enable);
    writer.set_pac(&auto.url, auto.enable);
    // Parse before staging: no fallible receipt construction is allowed after a possible write.
    let receipt = writer.receipt()?;
    let commit = writer.commit();
    let unlock = writer.finish();
    Ok(PrivilegedProxyApply {
        receipt,
        result: commit.and(unlock),
    })
}

pub(crate) fn clear_privileged_native_if_unchanged(
    receipt: &mut PrivilegedProxyReceipt,
) -> Result<bool> {
    let mut writer = match NativeProxyWriter::open_service(Some(&receipt.service_id)) {
        Ok(writer) => writer,
        Err(Error::NoActiveNetworkService) => return Ok(false),
        Err(error) => return Err(error),
    };
    let current = managed_proxy_fields(&writer.config.to_immutable())?;
    writer.set_global("", 0, "", false);
    writer.set_pac("", false);
    let disabled = managed_proxy_fields(&writer.config.to_immutable())?;
    let cleared = clear_owned_fields(receipt, &current, disabled, || writer.commit())?;
    writer.finish()?;
    Ok(cleared)
}

fn clear_owned_fields(
    receipt: &mut PrivilegedProxyReceipt,
    current: &ManagedProxyFields,
    disabled: ManagedProxyFields,
    commit: impl FnOnce() -> Result<()>,
) -> Result<bool> {
    if !receipt.states.contains(current) {
        return Ok(false);
    }
    // A failed apply can leave Disabled committed but not active. Retain that state too,
    // so a retry applies our own partial clear instead of mistaking it for a foreign write.
    if !receipt.states.contains(&disabled) {
        receipt.states.push(disabled);
    }
    commit()?;
    Ok(true)
}

/// Fixed path prevents `PATH` substitution in privileged callers.
const NETWORKSETUP: &str = "/usr/sbin/networksetup";

/// Admin-required exit code observed from `networksetup` on macOS 26.6.1.
const EXIT_REQUIRES_ADMIN: i32 = 14;

const WRITES_PER_PROXY_TYPE: u8 = 2;
const SYSTEM_PROXY_WRITES: u8 = 3 * WRITES_PER_PROXY_TYPE + 1;
const AUTO_PROXY_WRITES: u8 = 2;
const BYPASS_WRITES: u8 = 1;

/// Tracks accepted writes in one logical operation.
struct WriteSequence {
    completed: u8,
    total: u8,
}

impl WriteSequence {
    #[inline]
    const fn new(total: u8) -> Self {
        Self {
            completed: 0,
            total,
        }
    }

    #[inline]
    fn record(&mut self, outcome: Result<()>) -> Result<()> {
        match outcome {
            Ok(()) => {
                self.completed += 1;
                Ok(())
            }
            Err(source) => Err(Error::ProxyWrite {
                progress: WriteProgress {
                    completed: self.completed,
                    total: self.total,
                },
                source: Box::new(source),
            }),
        }
    }

    #[inline]
    fn run(&mut self, args: &[&str]) -> Result<()> {
        self.record(run_networksetup(args))
    }
}

#[inline]
fn run_networksetup(args: &[&str]) -> Result<()> {
    let output = Command::new(NETWORKSETUP)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()?;

    parse_networksetup_output(args, output)
}

#[inline]
fn parse_networksetup_output(args: &[&str], output: Output) -> Result<()> {
    if !output.status.success() {
        // Keep the exit status usable even when failure output is not UTF-8.
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);

        // `networksetup` may report failures on either stream.
        let details = [stdout.trim(), stderr.trim()]
            .into_iter()
            .filter(|part| !part.is_empty())
            .collect::<Vec<_>>()
            .join("\n");

        // Match both signals; exit code 2 is an authentication failure, not missing privileges.
        if details.contains("requires admin privileges")
            || output.status.code() == Some(EXIT_REQUIRES_ADMIN)
        {
            log::error!(
                "Admin privileges required to run networksetup with args: {:?}, error: {}",
                args,
                details
            );
            return Err(Error::RequiresAdminPrivileges);
        }

        log::error!(
            "networksetup failed with args: {:?}, status: {}, error: {}",
            args,
            output.status,
            details
        );
        return Err(Error::NetworkSetup(format!(
            "args={args:?}, status={}, error={details}",
            output.status
        )));
    }

    // Successful write output is unused and must not affect progress.
    Ok(())
}

#[inline]
fn set_proxy(
    writes: &mut WriteSequence,
    proxy: &Sysproxy,
    proxy_type: ProxyType,
    service: &str,
) -> Result<()> {
    let host = proxy.host.as_str();
    let port = format!("{}", proxy.port);
    let port = port.as_str();

    writes.run(&[proxy_type.as_set_str(), service, host, port])?;

    let enable = if proxy.enable { "on" } else { "off" };

    writes.run(&[proxy_type.as_state_cmd(), service, enable])?;

    Ok(())
}

#[inline]
fn set_bypass(writes: &mut WriteSequence, proxy: &Sysproxy, service: &str) -> Result<()> {
    let mut args = vec!["-setproxybypassdomains", service];
    let domains: Vec<&str> = if proxy.bypass.is_empty() {
        Vec::new()
    } else {
        proxy.bypass.split(",").collect()
    };
    args.extend(&domains);
    writes.run(&args)?;
    Ok(())
}

fn get_active_network_service() -> Result<CFString> {
    let scp = SCPreferences::default(&CFString::new("sysproxy-rs"));
    let service_uuid = get_active_network_service_uuid(&scp)?;
    unsafe {
        let service_ref = copy_network_service(&scp, &service_uuid)?;
        let name = network_service_name_from_ptr(SCNetworkServiceGetName(service_ref));
        CFRelease(service_ref);
        name.ok_or(Error::NetworkInterface)
    }
}

/// Copies a service by id; the caller releases it. The dynamic store can name a primary service
/// the preferences lack, such as a VPN's, and that reads as no usable service.
fn copy_network_service(
    preferences: &SCPreferences,
    service_id: &CFString,
) -> Result<SCNetworkServiceRef> {
    let service = unsafe {
        SCNetworkServiceCopy(
            preferences.as_concrete_TypeRef(),
            service_id.as_concrete_TypeRef(),
        )
    };
    if service.is_null() {
        debug!("network service {service_id} is not in the network preferences");
        return Err(Error::NoActiveNetworkService);
    }
    Ok(service)
}

unsafe fn network_service_name_from_ptr(name: CFStringRef) -> Option<CFString> {
    if name.is_null() {
        None
    } else {
        Some(unsafe { CFString::wrap_under_get_rule(name) })
    }
}

fn get_active_network_service_uuid(preferences: &SCPreferences) -> Result<CFString> {
    resolve_active_service(preferences, &read_primary_ipv4()?)
}

/// The IPv4 primary as the dynamic store names it.
struct PrimaryIpv4 {
    service: CFString,
    interface: Option<CFString>,
}

fn read_primary_ipv4() -> Result<PrimaryIpv4> {
    let store = SCDynamicStoreBuilder::new("sysproxy-rs")
        .build()
        .ok_or(Error::SCDynamicStore)?;
    let global_ipv4_key = CFString::from_static_string(network::PRIMARY_SERVICE_KEY);
    let dict = store
        .get(global_ipv4_key)
        .and_then(|value| value.downcast_into::<CFDictionary>())
        .ok_or(Error::NoActiveNetworkService)?;
    Ok(PrimaryIpv4 {
        service: dictionary_string(&dict, "PrimaryService").ok_or(Error::NoActiveNetworkService)?,
        interface: dictionary_string(&dict, "PrimaryInterface"),
    })
}

fn dictionary_string(dict: &CFDictionary, key: &'static str) -> Option<CFString> {
    let key = CFString::from_static_string(key);
    let value = dict.find(key.as_CFTypeRef() as *const _)?;
    unsafe { CFType::wrap_under_get_rule(*value as _) }.downcast_into::<CFString>()
}

/// Maps the primary to a service in the preferences, the only place proxy settings can be written.
///
/// `ipconfig set en0 DHCP` swaps the interface's configured IPv4 service for one ipconfigd names
/// after the method and interface, such as `DHCP-en0`, which the preferences lack. The interface's
/// configured service is still the one that holds its proxy settings, so fall back to it.
fn resolve_active_service(preferences: &SCPreferences, primary: &PrimaryIpv4) -> Result<CFString> {
    if let Ok(service) = copy_network_service(preferences, &primary.service) {
        unsafe { CFRelease(service.cast()) };
        return Ok(primary.service.clone());
    }
    let interface = primary
        .interface
        .as_ref()
        .ok_or(Error::NoActiveNetworkService)?
        .to_string();
    // Any other unknown primary, such as a VPN's or one deleted since it was read, still reads as
    // none rather than being swapped for whatever else is configured on the interface.
    if !is_ipconfig_service_on(&primary.service.to_string(), &interface) {
        return Err(Error::NoActiveNetworkService);
    }
    let (services, service_order) = current_set_services(preferences);
    let service = pick_service_on_interface(&services, &service_order, &interface)
        .ok_or(Error::NoActiveNetworkService)?;
    debug!(
        "primary service {} is not in the network preferences; using {} on {interface}",
        primary.service, service.id
    );
    Ok(CFString::new(&service.id))
}

/// The IPv4 methods `ipconfig set` accepts; `NONE` stops the interface's services instead.
const IPCONFIG_IPV4_METHODS: [&str; 6] =
    ["BOOTP", "DHCP", "FAILOVER", "INFORM", "LINKLOCAL", "MANUAL"];

/// Whether `service` is the `<method>-<interface>` id ipconfigd gives a service it started for
/// `ipconfig set` on `interface`.
fn is_ipconfig_service_on(service: &str, interface: &str) -> bool {
    !interface.is_empty()
        && service
            .strip_suffix(interface)
            .and_then(|method| method.strip_suffix('-'))
            .is_some_and(|method| IPCONFIG_IPV4_METHODS.contains(&method))
}

/// A service of the current network set.
#[derive(Debug)]
struct SetService {
    id: String,
    interface: Option<String>,
    enabled: bool,
}

/// Services of the current set, the only set configd applies, and the set's service order.
fn current_set_services(preferences: &SCPreferences) -> (Vec<SetService>, Vec<String>) {
    let set = unsafe { SCNetworkSetCopyCurrent(preferences.as_concrete_TypeRef()) };
    if set.is_null() {
        return (Vec::new(), Vec::new());
    }
    let set = unsafe { SCNetworkSet::wrap_under_create_rule(set) };
    let service_order = set
        .service_order()
        .iter()
        .map(|id| id.to_string())
        .collect();

    let services = unsafe { SCNetworkSetCopyServices(set.as_concrete_TypeRef()) };
    if services.is_null() {
        return (Vec::new(), service_order);
    }
    let services = unsafe { CFArray::<SCNetworkService>::wrap_under_create_rule(services) };
    let services = services
        .iter()
        .filter_map(|service| {
            Some(SetService {
                id: service.id()?.to_string(),
                interface: service
                    .network_interface()
                    .and_then(|interface| interface.bsd_name())
                    .map(|name| name.to_string()),
                // `SCNetworkService::enabled` inverts the result, so ask directly.
                enabled: unsafe { SCNetworkServiceGetEnabled(service.as_concrete_TypeRef()) } != 0,
            })
        })
        .collect();
    (services, service_order)
}

/// The enabled service on `interface` that ranks first in the service order, which is the one
/// configd prefers when several share the interface; unordered services rank last.
fn pick_service_on_interface<'a>(
    services: &'a [SetService],
    service_order: &[String],
    interface: &str,
) -> Option<&'a SetService> {
    let rank = |service: &SetService| {
        service_order
            .iter()
            .position(|id| *id == service.id)
            .unwrap_or(service_order.len())
    };
    services
        .iter()
        .filter(|service| service.enabled && service.interface.as_deref() == Some(interface))
        .min_by_key(|service| rank(service))
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

/// Resolve one proxy dictionary, preferring preferences and falling back to DynamicStore.
fn resolve_proxies_dict(
    scp: &SCPreferences,
    service_uuid: &CFString,
) -> Result<CFDictionary<CFString, CFType>> {
    match get_proxies_by_service_uuid(scp, service_uuid) {
        Ok(dict) => return Ok(dict),
        // `Setup:` mirrors the preferences, so it cannot hold a service they lack.
        Err(error @ Error::NoActiveNetworkService) => return Err(error),
        Err(_) => {}
    }

    let store = SCDynamicStoreBuilder::new("sysproxy-rs")
        .build()
        .ok_or(Error::SCDynamicStore)?;
    let proxy_key = CFString::new(&format!("Setup:/Network/Service/{service_uuid}/Proxies"));
    let proxies_cf_type = store.get(proxy_key).ok_or_else(|| {
        Error::ParseStr("Proxy settings not found in preferences or DynamicStore".into())
    })?;
    let proxies_dict_raw = proxies_cf_type
        .downcast_into::<CFDictionary>()
        .ok_or_else(|| Error::ParseStr("Not a dictionary".into()))?;

    Ok(unsafe { CFDictionary::wrap_under_get_rule(proxies_dict_raw.as_concrete_TypeRef()) })
}

fn get_proxies_by_service_uuid(
    scp: &SCPreferences,
    service_uuid: &CFString,
) -> Result<CFDictionary<CFString, CFType>> {
    unsafe {
        let service_ref = copy_network_service(scp, service_uuid)?;

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
fn a_service_missing_from_the_preferences_reads_as_no_active_service() {
    let scp = SCPreferences::default(&CFString::new("sysproxy-rs"));
    let configured: Vec<String> = SCNetworkService::get_services(&scp)
        .iter()
        .filter_map(|service| service.id().map(|id| id.to_string()))
        .collect();
    let mut unknown = String::from("gpd.pan");
    while configured.contains(&unknown) {
        unknown.push('_');
    }
    let result = resolve_proxies_dict(&scp, &CFString::new(&unknown));
    assert!(matches!(result, Err(Error::NoActiveNetworkService)));
}

/// Destructive and machine-dependent: changes the real Wi-Fi bypass list without restoring it.
#[test]
#[ignore = "destructive: rewrites the machine's real Wi-Fi bypass list without restoring it"]
fn test_set_bypass() {
    let proxy = Sysproxy {
        host: "proxy.example.com".into(),
        port: 8080,
        enable: true,
        bypass: "no".into(),
    };
    let result = proxy.set_bypass("Wi-Fi");
    if let Err(e) = result {
        assert!(matches!(
            leaf_error(&e),
            Some(Error::RequiresAdminPrivileges)
        ));
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
fn network_service_name_from_ptr_preserves_trailing_space() {
    let name = CFString::new("Wi-Fi ");
    let service_name = unsafe { network_service_name_from_ptr(name.as_concrete_TypeRef()) }
        .map(|name| name.to_string());

    assert_eq!(service_name, Some("Wi-Fi ".to_string()));
}

#[test]
fn networksetup_nonzero_exit_returns_error() {
    use std::os::unix::process::ExitStatusExt;
    use std::process::{ExitStatus, Output};

    for (stdout, stderr) in [
        (
            b"** Error: The parameters were not valid.\n".to_vec(),
            Vec::new(),
        ),
        (
            Vec::new(),
            b"** Error: The parameters were not valid.\n".to_vec(),
        ),
    ] {
        let output = Output {
            status: ExitStatus::from_raw(4 << 8),
            stdout,
            stderr,
        };

        let result = parse_networksetup_output(&["-setwebproxy", "Wi-Fi"], output);

        assert!(matches!(
            result,
            Err(Error::NetworkSetup(message))
                if message.contains("The parameters were not valid")
        ));
    }
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

/// Build an `ExitStatus` without running `networksetup`.
#[cfg(test)]
fn exit_status(code: i32) -> std::process::ExitStatus {
    use std::os::unix::process::ExitStatusExt as _;
    std::process::ExitStatus::from_raw(code << 8)
}

#[test]
fn admin_failure_is_recognised_from_the_exit_code_alone() {
    let output = Output {
        status: exit_status(EXIT_REQUIRES_ADMIN),
        stdout: Vec::new(),
        stderr: Vec::new(),
    };

    assert!(matches!(
        parse_networksetup_output(&["-setwebproxystate", "Wi-Fi", "off"], output),
        Err(Error::RequiresAdminPrivileges)
    ));
}

#[test]
fn admin_failure_is_recognised_from_the_message_alone() {
    let output = Output {
        status: exit_status(1),
        stdout: b"** Error: Command requires admin privileges.".to_vec(),
        stderr: Vec::new(),
    };

    assert!(matches!(
        parse_networksetup_output(&["-setwebproxystate", "Wi-Fi", "off"], output),
        Err(Error::RequiresAdminPrivileges)
    ));
}

#[test]
fn authentication_failures_are_not_reported_as_missing_admin_rights() {
    let output = Output {
        status: exit_status(2),
        stdout: b"** Error: An error occurred while authenticating.".to_vec(),
        stderr: Vec::new(),
    };

    assert!(matches!(
        parse_networksetup_output(&["-setwebproxystate", "Wi-Fi", "off"], output),
        Err(Error::NetworkSetup(_))
    ));
}

#[test]
fn only_the_admin_exit_code_is_treated_as_a_privilege_failure() {
    assert_eq!(EXIT_REQUIRES_ADMIN, 14);

    for code in [13, 15] {
        let output = Output {
            status: exit_status(code),
            stdout: Vec::new(),
            stderr: Vec::new(),
        };

        assert!(
            matches!(
                parse_networksetup_output(&["-setwebproxystate", "Wi-Fi", "off"], output),
                Err(Error::NetworkSetup(_))
            ),
            "exit code {code} must not be classified as a privilege failure"
        );
    }
}

#[test]
fn the_exit_code_still_classifies_when_the_output_is_not_valid_utf8() {
    for (stdout, stderr) in [
        (vec![0xff, 0xfe, 0x00], Vec::new()),
        (Vec::new(), vec![0xff, 0xfe, 0x00]),
    ] {
        let output = Output {
            status: exit_status(EXIT_REQUIRES_ADMIN),
            stdout,
            stderr,
        };

        assert!(matches!(
            parse_networksetup_output(&["-setwebproxystate", "Wi-Fi", "off"], output),
            Err(Error::RequiresAdminPrivileges)
        ));
    }
}

#[test]
fn a_failure_before_any_write_reports_that_nothing_landed() {
    let mut writes = WriteSequence::new(SYSTEM_PROXY_WRITES);

    let failure = writes.record(Err(Error::RequiresAdminPrivileges)).err();

    assert!(
        matches!(
            &failure,
            Some(Error::ProxyWrite { progress, .. })
                if progress.nothing_written() && progress.total() == SYSTEM_PROXY_WRITES
        ),
        "unexpected failure shape: {failure:?}"
    );
}

#[test]
fn progress_counts_the_writes_that_already_landed() {
    let mut writes = WriteSequence::new(SYSTEM_PROXY_WRITES);

    assert!(writes.record(Ok(())).is_ok());
    assert!(writes.record(Ok(())).is_ok());
    assert!(writes.record(Ok(())).is_ok());

    let failure = writes.record(Err(Error::RequiresAdminPrivileges)).err();

    assert!(
        matches!(
            &failure,
            Some(Error::ProxyWrite { progress, .. })
                if !progress.nothing_written() && progress.completed() == 3
        ),
        "unexpected failure shape: {failure:?}"
    );
}

/// Return the first crate error in an error's source chain.
#[cfg(test)]
fn leaf_error(err: &Error) -> Option<&Error> {
    use std::error::Error as StdError;

    let mut current: Option<&(dyn StdError + 'static)> = StdError::source(err);
    while let Some(source) = current {
        if let Some(leaf) = source.downcast_ref::<Error>() {
            return Some(leaf);
        }
        current = source.source();
    }
    None
}

#[test]
fn the_underlying_failure_stays_reachable_through_the_source_chain() {
    let mut writes = WriteSequence::new(SYSTEM_PROXY_WRITES);

    let failure = writes.record(Err(Error::RequiresAdminPrivileges)).err();

    let reached = failure.as_ref().and_then(leaf_error);
    assert!(
        matches!(reached, Some(Error::RequiresAdminPrivileges)),
        "leaf not reachable through the source chain: {failure:?}"
    );
}

#[test]
fn the_wrapper_does_not_repeat_the_leaf_message() {
    let mut writes = WriteSequence::new(SYSTEM_PROXY_WRITES);

    let failure = writes.record(Err(Error::RequiresAdminPrivileges)).err();
    let rendered = failure.map(|err| err.to_string()).unwrap_or_default();

    assert!(
        !rendered.contains("admin privileges"),
        "wrapper Display should not inline the leaf: {rendered}"
    );
    assert!(rendered.contains("0 of 7 writes completed"), "{rendered}");
}

#[test]
fn a_successful_write_is_not_failed_by_output_it_cannot_decode() {
    let output = Output {
        status: exit_status(0),
        stdout: vec![0xff, 0xfe, 0x00],
        stderr: vec![0xff, 0xfe, 0x00],
    };

    assert!(
        parse_networksetup_output(&["-setwebproxystate", "Wi-Fi", "off"], output).is_ok(),
        "a command that exited 0 must be reported as success"
    );
}

#[test]
fn a_successful_write_advances_the_progress_counter() {
    let mut writes = WriteSequence::new(SYSTEM_PROXY_WRITES);

    let accepted = parse_networksetup_output(
        &["-setwebproxystate", "Wi-Fi", "off"],
        Output {
            status: exit_status(0),
            stdout: vec![0xff, 0xfe, 0x00],
            stderr: Vec::new(),
        },
    );
    assert!(writes.record(accepted).is_ok());

    let failure = writes.record(Err(Error::RequiresAdminPrivileges)).err();

    assert!(
        matches!(
            &failure,
            Some(Error::ProxyWrite { progress, .. }) if progress.completed() == 1
        ),
        "unexpected failure shape: {failure:?}"
    );
}

#[test]
fn managed_proxy_fields_preserve_raw_bypass_and_absent_values() -> Result<()> {
    let key = CFString::from_static_string("ExceptionsList");
    let joined = CFDictionary::from_CFType_pairs(&[(
        key.clone(),
        CFArray::from_CFTypes(&[CFString::new("a,b")]).as_CFType(),
    )]);
    let split = CFDictionary::from_CFType_pairs(&[(
        key,
        CFArray::from_CFTypes(&[CFString::new("a"), CFString::new("b")]).as_CFType(),
    )]);
    assert_eq!(
        parse_bypass_from_dict(&joined)?.join(","),
        parse_bypass_from_dict(&split)?.join(",")
    );
    assert_ne!(
        managed_proxy_fields(&joined)?,
        managed_proxy_fields(&split)?
    );
    let missing = CFDictionary::<CFString, CFType>::from_CFType_pairs(&[]);
    let disabled = CFDictionary::from_CFType_pairs(&[(
        CFString::from_static_string("HTTPEnable"),
        CFNumber::from(0).as_CFType(),
    )]);
    assert_ne!(
        managed_proxy_fields(&missing)?,
        managed_proxy_fields(&disabled)?
    );
    Ok(())
}

#[test]
fn partial_owned_clear_retries_its_committed_disabled_state() -> Result<()> {
    let enabled = managed_proxy_fields(&CFDictionary::from_CFType_pairs(&[(
        CFString::from_static_string("HTTPEnable"),
        CFNumber::from(1).as_CFType(),
    )]))?;
    let disabled = managed_proxy_fields(&CFDictionary::from_CFType_pairs(&[(
        CFString::from_static_string("HTTPEnable"),
        CFNumber::from(0).as_CFType(),
    )]))?;
    let mut receipt = PrivilegedProxyReceipt {
        service_id: "isolated-fixture".into(),
        states: vec![enabled.clone()],
    };
    let mut committed = enabled.clone();
    assert!(
        clear_owned_fields(&mut receipt, &enabled, disabled.clone(), || {
            committed = disabled.clone();
            Err(Error::SystemConfiguration(
                "fixture apply failure after commit",
            ))
        })
        .is_err()
    );
    let mut applied = false;
    assert!(clear_owned_fields(
        &mut receipt,
        &committed,
        disabled.clone(),
        || {
            applied = true;
            Ok(())
        }
    )?);
    assert!(applied);
    let foreign = managed_proxy_fields(&CFDictionary::<CFString, CFType>::from_CFType_pairs(&[]))?;
    assert!(!clear_owned_fields(
        &mut receipt,
        &foreign,
        disabled,
        || {
            Err(Error::SystemConfiguration(
                "foreign state must not be written",
            ))
        }
    )?);
    assert_eq!(receipt.states.len(), 2);
    Ok(())
}
