use crate::{Error, ProxySnapshot, Result, Sysproxy};
use system_configuration::{
    core_foundation::{
        array::CFArray,
        base::TCFType,
        dictionary::CFDictionary,
        runloop::{CFRunLoop, CFRunLoopSource, CFRunLoopSourceInvalidate, kCFRunLoopCommonModes},
        string::CFString,
    },
    dynamic_store::{SCDynamicStore, SCDynamicStoreBuilder, SCDynamicStoreCallBackContext},
};

pub(super) const PRIMARY_SERVICE_KEY: &str = "State:/Network/Global/IPv4";

#[derive(Clone, PartialEq, Eq)]
struct NetworkState {
    service: Option<String>,
    interface: Option<String>,
    proxies: Option<ProxySnapshot>,
}

fn network_state(store: &SCDynamicStore) -> NetworkState {
    let dictionary = store
        .get(CFString::from_static_string(PRIMARY_SERVICE_KEY))
        .and_then(|value| value.downcast_into::<CFDictionary>());
    let field = |name| {
        dictionary.as_ref().and_then(|dictionary| {
            super::dictionary_string(dictionary, name).map(|value| value.to_string())
        })
    };
    NetworkState {
        service: field("PrimaryService"),
        interface: field("PrimaryInterface"),
        // None also records a service that exists in IPv4 state but is not configured yet.
        proxies: Sysproxy::snapshot().ok(),
    }
}

struct ServiceChange<F> {
    previous: NetworkState,
    callback: F,
}

impl<F: FnMut()> ServiceChange<F> {
    fn observe(&mut self, current: NetworkState) {
        if self.previous == current {
            return;
        }
        // Record the transition before invoking a callback that may write network preferences.
        self.previous = current;
        (self.callback)();
    }
}

/// Watches primary IPv4 network changes on the application's main run loop.
/// Dropping the monitor removes the subscription; an executing callback may finish. Drop it on
/// the main thread while that loop is running: SCDynamicStore does not document its cancel path
/// as safe against a callback being delivered concurrently. Dropping elsewhere stays memory-safe.
#[must_use = "dropping the monitor stops network notifications"]
pub struct NetworkServiceMonitor {
    source: CFRunLoopSource,
}

// The source stays on the main run loop. Core Foundation allows invalidation from other
// threads, and the callback is Send so its context can also be released there.
unsafe impl Send for NetworkServiceMonitor {}

impl NetworkServiceMonitor {
    /// Returns once subscribed. The application must run its main CFRunLoop to receive events.
    /// The callback runs when the primary service or its proxy settings change. Repeated
    /// notifications with unchanged state are ignored. It should return promptly.
    pub fn start<F: FnMut() + Send + 'static>(on_change: F) -> Result<Self> {
        let initial_store = SCDynamicStoreBuilder::new("sysproxy-rs network monitor baseline")
            .build()
            .ok_or(Error::SCDynamicStore)?;
        let changes = ServiceChange {
            previous: network_state(&initial_store),
            callback: on_change,
        };
        let store = SCDynamicStoreBuilder::new("sysproxy-rs network monitor")
            .callback_context(SCDynamicStoreCallBackContext {
                callout: |store, _, changes: &mut ServiceChange<F>| {
                    changes.observe(network_state(&store));
                },
                info: changes,
            })
            .build()
            .ok_or(Error::SCDynamicStore)?;
        let keys = CFArray::from_CFTypes(&[CFString::from_static_string(PRIMARY_SERVICE_KEY)]);
        let patterns = CFArray::from_CFTypes(&[CFString::from_static_string(
            "Setup:/Network/Service/[^/]+/Proxies",
        )]);
        if !store.set_notification_keys(&keys, &patterns) {
            return Err(Error::SCDynamicStore);
        }
        let source = store
            .create_run_loop_source()
            .ok_or(Error::SCDynamicStore)?;
        CFRunLoop::get_main().add_source(&source, unsafe { kCFRunLoopCommonModes });
        Ok(Self { source })
    }
}

impl Drop for NetworkServiceMonitor {
    fn drop(&mut self) {
        unsafe { CFRunLoopSourceInvalidate(self.source.as_concrete_TypeRef()) };
    }
}

#[test]
#[allow(clippy::unwrap_used)]
fn dropping_monitor_removes_subscription_and_releases_callback() {
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };

    let called = Arc::new(AtomicBool::new(false));
    let callback_state = Arc::clone(&called);
    let monitor =
        NetworkServiceMonitor::start(move || callback_state.store(true, Ordering::Relaxed))
            .unwrap();
    let source = monitor.source.clone();
    let run_loop = CFRunLoop::get_main();
    assert!(run_loop.contains_source(&source, unsafe { kCFRunLoopCommonModes }));
    assert_eq!(Arc::strong_count(&called), 2);

    drop(monitor);
    assert!(!run_loop.contains_source(&source, unsafe { kCFRunLoopCommonModes }));
    drop(source);
    assert_eq!(Arc::strong_count(&called), 1);
    assert!(!called.load(Ordering::Relaxed));
}

#[cfg(test)]
fn state(service: Option<&str>, proxies: Option<ProxySnapshot>) -> NetworkState {
    NetworkState {
        service: service.map(str::to_owned),
        interface: service.map(|_| "en0".to_owned()),
        proxies,
    }
}

#[test]
fn repeated_notifications_for_the_same_state_do_not_reapply_proxy() {
    let mut calls = 0;
    {
        let current = state(Some("wifi"), Some(ProxySnapshot::default()));
        let mut changes = ServiceChange {
            previous: current.clone(),
            callback: || calls += 1,
        };
        for _ in 0..100 {
            changes.observe(current.clone());
        }
    }
    assert_eq!(calls, 0);
}

#[test]
fn service_switches_and_reconnection_still_notify() {
    let mut calls = 0;
    {
        let mut changes = ServiceChange {
            previous: state(None, None),
            callback: || calls += 1,
        };
        for service in [
            None,
            Some("wifi"),
            Some("wifi"),
            Some("ethernet"),
            None,
            None,
            Some("ethernet"),
        ] {
            changes.observe(state(service, None));
        }
    }
    assert_eq!(calls, 4);
}

#[test]
fn the_same_service_becoming_ready_notifies() {
    let mut calls = 0;
    {
        let mut changes = ServiceChange {
            previous: state(Some("wifi"), None),
            callback: || calls += 1,
        };
        changes.observe(state(Some("wifi"), Some(ProxySnapshot::default())));
    }
    assert_eq!(calls, 1);
}

#[test]
fn proxy_reset_and_recovery_on_the_same_service_do_not_loop() {
    let mut calls = 0;
    {
        let mut enabled = ProxySnapshot::default();
        enabled.http.switched_on = true;
        enabled.http.enable = true;
        enabled.http.host = "127.0.0.1".to_owned();
        enabled.http.port = 7897;
        let configured = state(Some("wifi"), Some(enabled));
        let mut changes = ServiceChange {
            previous: configured.clone(),
            callback: || calls += 1,
        };
        changes.observe(state(Some("wifi"), Some(ProxySnapshot::default())));
        // The consumer restores the proxy asynchronously; its own write is observed once.
        changes.observe(configured.clone());
        for _ in 0..100 {
            changes.observe(configured.clone());
        }
    }
    assert_eq!(calls, 2);
}
