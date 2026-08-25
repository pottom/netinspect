//! The `Snapshot` model: the contract between the platform layer and everything
//! above it.
//!
//! This module depends on nothing but `serde`. It must never gain a platform
//! dependency, a `cfg` attribute, or an `unsafe` block. A field that some
//! platform cannot fill is an `Option`, and the renderer omits the row — that
//! absence is the normal shape of the problem, not an exceptional case.

// The model is the contract, so it describes the whole report up front —
// including the parts the `routes` and `listen` collectors will fill in later.
// Remove this once every field has a producer.
#![allow(dead_code)]

use serde::Serialize;

/// JSON schema version. Bumping this is a breaking change (see spec 8).
pub const SCHEMA: u32 = 1;

// ---------------------------------------------------------------------------
// Top level
// ---------------------------------------------------------------------------

/// The full report produced by the default command.
#[derive(Debug, Clone, Serialize)]
pub struct Snapshot {
    pub schema: u32,
    pub version: String,
    pub timestamp: String,
    pub interfaces: Vec<Interface>,
    pub dns: DnsConfig,
    pub reachability: Option<Reachability>,
    pub public: Option<PublicAddress>,
    pub update: Option<UpdateInfo>,
}

/// The envelope shared by every subcommand that emits JSON.
#[derive(Debug, Clone, Serialize)]
pub struct Envelope {
    pub schema: u32,
    pub version: String,
    pub timestamp: String,
}

// ---------------------------------------------------------------------------
// Interfaces
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
pub struct Interface {
    pub name: String,
    /// The user-visible service name ("Wi-Fi"). `None` when the system has no
    /// name for this interface, which is the case for kernel-internal
    /// pseudo-interfaces the user has never seen.
    pub display_name: Option<String>,
    pub kind: InterfaceKind,
    pub status: InterfaceStatus,
    pub ipv4: Vec<Ipv4Entry>,
    pub ipv6: Vec<Ipv6Entry>,
    pub gateway: Option<String>,
    pub mac: Option<String>,
    pub mtu: Option<u32>,
    pub dhcp: Option<DhcpLease>,
    pub wifi: Option<WifiDetail>,
    pub vpn: Option<VpnDetail>,
    pub is_default_route: bool,
}

impl Interface {
    /// True when the interface carries at least one address and is not down.
    pub fn is_active(&self) -> bool {
        matches!(
            self.status,
            InterfaceStatus::Connected | InterfaceStatus::Up
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum InterfaceKind {
    Wifi,
    Ethernet,
    Vpn,
    Bridge,
    Loopback,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InterfaceStatus {
    Connected,
    Up,
    NoCable,
    Inactive,
    Disabled,
}

impl InterfaceStatus {
    pub fn label(self) -> &'static str {
        match self {
            InterfaceStatus::Connected => "connected",
            InterfaceStatus::Up => "up",
            InterfaceStatus::NoCable => "no cable",
            InterfaceStatus::Inactive => "inactive",
            InterfaceStatus::Disabled => "disabled",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Ipv4Entry {
    pub address: String,
    pub prefix_len: u8,
    pub source: AddressSource,
}

#[derive(Debug, Clone, Serialize)]
pub struct Ipv6Entry {
    pub address: String,
    pub prefix_len: u8,
    pub scope: Ipv6Scope,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum AddressSource {
    Dhcp,
    Manual,
    Linklocal,
}

impl AddressSource {
    pub fn label(self) -> &'static str {
        match self {
            AddressSource::Dhcp => "dhcp",
            AddressSource::Manual => "manual",
            AddressSource::Linklocal => "link-local",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Ipv6Scope {
    Global,
    Link,
}

/// A DHCP lease. On macOS 15+ the expiry is not readable without root, so both
/// fields are routinely `None` even when the address source is `Dhcp`.
#[derive(Debug, Clone, Serialize)]
pub struct DhcpLease {
    pub expires_at: Option<String>,
    pub seconds_remaining: Option<i64>,
}

// ---------------------------------------------------------------------------
// Wi-Fi
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
pub struct WifiDetail {
    pub ssid: Option<String>,
    pub ssid_source: Option<SsidSource>,
    pub rssi_dbm: Option<i32>,
    pub phy_mode: Option<String>,
    pub rate_mbps: Option<u32>,
}

impl WifiDetail {
    /// True when nothing at all could be read; the renderer omits the row.
    pub fn is_empty(&self) -> bool {
        self.ssid.is_none()
            && self.rssi_dbm.is_none()
            && self.phy_mode.is_none()
            && self.rate_mbps.is_none()
    }
}

/// Where an SSID came from. A user should never have to guess whether a value
/// came from a supported API or a scraped command.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SsidSource {
    /// `CWInterface.ssid()` — the supported API.
    #[serde(rename = "corewlan")]
    CoreWlan,
    /// The `CachedScanRecord` blob under `State:/Network/Interface/<if>/AirPort`.
    /// Native (no subprocess) but undocumented; strictly best-effort.
    #[serde(rename = "scdynamicstore")]
    DynamicStore,
    #[serde(rename = "helper:networksetup")]
    HelperNetworksetup,
    #[serde(rename = "helper:ipconfig")]
    HelperIpconfig,
    #[serde(rename = "helper:system_profiler")]
    HelperSystemProfiler,
}

impl SsidSource {
    /// The `via …` disclosure shown on the network row's continuation line.
    /// `None` for the supported API, which needs no disclosure.
    pub fn annotation(self) -> Option<&'static str> {
        match self {
            SsidSource::CoreWlan => None,
            SsidSource::DynamicStore => Some("via scan cache"),
            SsidSource::HelperNetworksetup => Some("via networksetup"),
            SsidSource::HelperIpconfig => Some("via ipconfig"),
            SsidSource::HelperSystemProfiler => Some("via system_profiler"),
        }
    }
}

// ---------------------------------------------------------------------------
// VPN
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
pub struct VpnDetail {
    pub protocol: Option<String>,
    pub endpoint: Option<String>,
    pub last_handshake_seconds: Option<u64>,
}

// ---------------------------------------------------------------------------
// DNS
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
pub struct DnsConfig {
    pub servers: Vec<String>,
    pub search_domains: Vec<String>,
    pub proxy: Option<String>,
    pub split_dns_scopes: u32,
}

// ---------------------------------------------------------------------------
// Reachability
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
pub struct Reachability {
    /// `None` means the stage was never attempted, which is not a failure.
    pub link: Option<Stage>,
    pub gateway: Option<Stage>,
    pub dns: Option<Stage>,
    pub http: Option<HttpStage>,
    pub state: ReachabilityState,
    pub captive_portal: Option<CaptivePortal>,
}

#[derive(Debug, Clone, Copy, Serialize)]
pub struct Stage {
    pub ok: bool,
    pub ms: Option<u64>,
}

#[derive(Debug, Clone, Copy, Serialize)]
pub struct HttpStage {
    pub ok: bool,
    pub ms: Option<u64>,
    pub status: Option<u16>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReachabilityState {
    Online,
    CaptivePortal,
    DnsFailure,
    GatewayUnreachable,
    LinkDown,
    Unknown,
}

#[derive(Debug, Clone, Serialize)]
pub struct CaptivePortal {
    pub login_url: String,
}

// ---------------------------------------------------------------------------
// Public address
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
pub struct PublicAddress {
    pub ipv4: Option<String>,
    pub ipv6: Option<String>,
    pub asn: Option<String>,
    pub org: Option<String>,
    pub city: Option<String>,
    pub region: Option<String>,
    pub country: Option<String>,
    pub latitude: Option<f64>,
    pub longitude: Option<f64>,
    pub accuracy_km: Option<u32>,
    pub timezone: Option<String>,
    pub timezone_matches_system: Option<bool>,
    pub via_vpn: Option<bool>,
    pub cached_at: Option<String>,
}

// ---------------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Family {
    Inet,
    Inet6,
}

#[derive(Debug, Clone, Serialize)]
pub struct Route {
    pub family: Family,
    pub destination: String,
    pub is_default: bool,
    pub gateway: Option<String>,
    pub gateway_kind: GatewayKind,
    pub interface: Option<String>,
    pub flags: String,
    pub flags_decoded: Vec<String>,
    pub expires_in_seconds: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum GatewayKind {
    Address,
    Link,
    Mac,
    None,
}

#[derive(Debug, Clone, Serialize)]
pub struct RouteSummary {
    pub total: usize,
    pub default_gateways: usize,
    pub split_tunnel: bool,
}

// ---------------------------------------------------------------------------
// Sockets
// ---------------------------------------------------------------------------

/// A socket table. Carries its own attribution completeness, because both macOS
/// and Linux have the same partial-privilege problem expressed differently.
#[derive(Debug, Clone, Serialize)]
pub struct SocketTable {
    pub sockets: Vec<SocketEntry>,
    pub summary: SocketSummary,
}

#[derive(Debug, Clone, Serialize)]
pub struct SocketEntry {
    pub protocol: Protocol,
    pub family: Family,
    pub address: String,
    pub port: u16,
    pub state: String,
    pub exposure: Exposure,
    /// `None` when ownership could not be determined. This must never be
    /// conflated with "no process".
    pub process: Option<ProcessInfo>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Tcp,
    Udp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Exposure {
    Wildcard,
    Loopback,
    Interface,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProcessInfo {
    pub name: String,
    pub pid: i32,
    pub uid: u32,
    pub user: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SocketSummary {
    pub total: usize,
    pub wildcard: usize,
    pub loopback: usize,
    pub interface: usize,
    pub unattributed: usize,
}

/// What `Platform::sockets` should collect.
#[derive(Debug, Clone, Copy, Default)]
pub struct SocketFilter {
    pub tcp: bool,
    pub udp: bool,
    /// Include established connections, not just listeners.
    pub include_established: bool,
}

// ---------------------------------------------------------------------------
// Firewall
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, Serialize)]
pub struct FirewallState {
    pub state: FirewallMode,
    pub block_all_incoming: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FirewallMode {
    Off,
    On,
    BlockAll,
    /// No trustworthy source. Never render this as "off": reporting "off" when
    /// you do not know turns a security check into a false reassurance.
    Unknown,
}

// ---------------------------------------------------------------------------
// Update
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
pub struct UpdateInfo {
    pub current: String,
    pub latest: Option<String>,
    pub available: bool,
}
