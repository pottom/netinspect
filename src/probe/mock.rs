//! A network that never touches a socket.
//!
//! Every shape the ladder has to distinguish — a clean 204, a redirect, an
//! intercepted 200, a filtered port 80, a dead resolver, a silent gateway — is
//! a constructor here, so the ladder's behaviour is asserted rather than
//! observed on whatever network the test machine happens to be on.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use super::{Connector, HttpClient, HttpReply, ProbeError, Resolver};

#[derive(Debug, Clone)]
pub struct MockNetwork {
    pub gateway_answers: bool,
    pub dns_answers: bool,
    /// Every name resolves to this one address.
    pub dns_hijacked: bool,
    pub http: Option<HttpReply>,
    /// Sleep past any timeout, as a badly behaved implementation would.
    pub stalls: bool,
}

impl MockNetwork {
    fn base() -> Self {
        MockNetwork {
            gateway_answers: true,
            dns_answers: true,
            dns_hijacked: false,
            http: None,
            stalls: false,
        }
    }

    async fn stall_if_asked(&self) {
        if self.stalls {
            tokio::time::sleep(Duration::from_secs(30)).await;
        }
    }

    pub fn online() -> Self {
        MockNetwork {
            http: Some(HttpReply {
                status: 204,
                location: None,
                body: String::new(),
            }),
            ..Self::base()
        }
    }

    pub fn redirect() -> Self {
        MockNetwork {
            http: Some(HttpReply {
                status: 302,
                location: Some("http://wifi.example.net/login".to_owned()),
                body: String::new(),
            }),
            ..Self::base()
        }
    }

    pub fn interception() -> Self {
        MockNetwork {
            http: Some(HttpReply {
                status: 200,
                location: None,
                body: "<html>Please sign in to continue</html>".to_owned(),
            }),
            ..Self::base()
        }
    }

    /// Port 80 filtered, everything else working.
    pub fn http_blocked() -> Self {
        MockNetwork {
            http: None,
            ..Self::base()
        }
    }

    pub fn dns_broken() -> Self {
        MockNetwork {
            dns_answers: false,
            ..Self::online()
        }
    }

    pub fn gateway_down() -> Self {
        MockNetwork {
            gateway_answers: false,
            ..Self::online()
        }
    }

    /// Ignores every timeout it is handed. The ladder must bound it anyway.
    pub fn stalling() -> Self {
        MockNetwork {
            stalls: true,
            ..Self::online()
        }
    }

    pub fn hijacked_dns() -> Self {
        MockNetwork {
            dns_hijacked: true,
            ..Self::online()
        }
    }
}

#[async_trait::async_trait]
impl Connector for MockNetwork {
    async fn reachable(&self, _address: SocketAddr, _timeout: Duration) -> bool {
        self.stall_if_asked().await;
        self.gateway_answers
    }
}

#[async_trait::async_trait]
impl Resolver for MockNetwork {
    async fn resolve(
        &self,
        _servers: &[IpAddr],
        name: &str,
        _timeout: Duration,
    ) -> Result<Vec<IpAddr>, ProbeError> {
        self.stall_if_asked().await;
        if !self.dns_answers {
            return Err(ProbeError::Failed("no answer".to_owned()));
        }
        if self.dns_hijacked {
            return Ok(vec!["10.0.0.1".parse().unwrap()]);
        }
        Ok(match name {
            super::CONTROL_HOST => vec!["93.184.216.34".parse().unwrap()],
            _ => vec!["17.253.144.10".parse().unwrap()],
        })
    }
}

#[async_trait::async_trait]
impl HttpClient for MockNetwork {
    async fn get(&self, _url: &str, _timeout: Duration) -> Result<HttpReply, ProbeError> {
        self.stall_if_asked().await;
        self.http
            .clone()
            .ok_or_else(|| ProbeError::Failed("connection refused".to_owned()))
    }
}
