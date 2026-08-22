# sysproxy-rs

A library for set/get system proxy. Supports Windows, macOS and linux (via gsettings/kconfig).

`ProxyConfig::apply` provides one desired-state API while retaining each platform's established
user-facing behavior. In particular, macOS continues to use Apple's signed `networksetup` tool so
ordinary applications retain its authorization behavior.

The default `platform` feature enables the Linux, macOS, and Windows backends for compatibility.
Consumers that only need one target can disable default features and enable `linux`, `macos`, or
`windows` explicitly.

Privileged macOS helpers and services can enable the non-default `privileged-macos` feature and
call `ProxyConfig::apply_privileged_native` to update HTTP, HTTPS, SOCKS, PAC, and bypass settings
in one SystemConfiguration transaction without starting an external process. This explicit API
does not present authorization UI; callers must already have permission to write system network
preferences.
