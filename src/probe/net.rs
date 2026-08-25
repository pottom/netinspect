//! The real network behind the probe traits.
//!
//! Portable: tokio, reqwest over rustls, and hickory. Nothing here touches a
//! platform API, which is why the ladder above it never had to.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use hickory_resolver::config::{NameServerConfig, ResolverConfig};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::TokioResolver;

use super::{Connector, HttpClient, HttpReply, ProbeError, Resolver};

pub struct Net {
    client: reqwest::Client,
}

impl Net {
    pub fn new() -> Result<Self, ProbeError> {
        let client = reqwest::Client::builder()
            // A redirect is the answer, not something to follow.
            .redirect(reqwest::redirect::Policy::none())
            .user_agent(concat!("netinspect/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|e| ProbeError::Failed(e.to_string()))?;
        Ok(Net { client })
    }
}

#[async_trait::async_trait]
impl Connector for Net {
    async fn reachable(&self, address: SocketAddr, timeout: Duration) -> bool {
        use std::io::ErrorKind;

        match tokio::time::timeout(timeout, tokio::net::TcpStream::connect(address)).await {
            Ok(Ok(_)) => true,
            // The host answered — it refused, but it is there, which is the
            // question. Only silence means unreachable.
            Ok(Err(error)) => matches!(
                error.kind(),
                ErrorKind::ConnectionRefused | ErrorKind::ConnectionReset
            ),
            Err(_) => false,
        }
    }
}

#[async_trait::async_trait]
impl Resolver for Net {
    async fn resolve(
        &self,
        servers: &[IpAddr],
        name: &str,
        timeout: Duration,
    ) -> Result<Vec<IpAddr>, ProbeError> {
        // Ask the resolvers the system is configured with, not whatever this
        // process would have used by default.
        let name_servers = servers
            .iter()
            .map(|ip| NameServerConfig::udp_and_tcp(*ip))
            .collect();
        let config = ResolverConfig::from_parts(None, Vec::new(), name_servers);

        let mut builder =
            TokioResolver::builder_with_config(config, TokioRuntimeProvider::default());
        builder.options_mut().timeout = timeout;
        // One shot: retrying inside the resolver would blow the stage budget.
        builder.options_mut().attempts = 1;
        let resolver = builder
            .build()
            .map_err(|e| ProbeError::Failed(e.to_string()))?;

        match tokio::time::timeout(timeout, resolver.lookup_ip(name)).await {
            Ok(Ok(lookup)) => Ok(lookup.iter().collect()),
            Ok(Err(error)) => Err(ProbeError::Failed(error.to_string())),
            Err(_) => Err(ProbeError::Timeout),
        }
    }
}

#[async_trait::async_trait]
impl HttpClient for Net {
    async fn get(&self, url: &str, timeout: Duration) -> Result<HttpReply, ProbeError> {
        let request = self.client.get(url).timeout(timeout).send();
        let response = match tokio::time::timeout(timeout, request).await {
            Ok(Ok(response)) => response,
            Ok(Err(error)) => return Err(ProbeError::Failed(error.to_string())),
            Err(_) => return Err(ProbeError::Timeout),
        };

        let status = response.status().as_u16();
        let location = response
            .headers()
            .get(reqwest::header::LOCATION)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        // The detector page is a few dozen bytes; a portal's is a web page.
        // Either way only the first kilobyte is ever read.
        let body = response
            .text()
            .await
            .map(|text| text.chars().take(1024).collect())
            .unwrap_or_default();

        Ok(HttpReply {
            status,
            location,
            body,
        })
    }
}
