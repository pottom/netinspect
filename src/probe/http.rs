//! Stage 4 — HTTP, and the captive portal verdict.
//!
//! Redirects are disabled because a redirect *is* the answer. The page asked
//! for is Apple's hotspot detector, which returns a known body; anything else
//! coming back on that URL is something else answering for it.

use crate::model::ReachabilityState;

use super::{HttpReply, ProbeError, PROBE_URL};

/// The body Apple's endpoint returns when nothing is in the way.
const EXPECTED: &str = "Success";

#[derive(Debug, Clone, PartialEq)]
pub struct Verdict {
    /// Whether the stage itself completed. A filtered port 80 is `false` while
    /// the machine is still online.
    pub reached: bool,
    pub state: ReachabilityState,
    pub login_url: Option<String>,
}

pub fn classify(reply: Result<&HttpReply, &ProbeError>, every_name_one_address: bool) -> Verdict {
    // The resolver already gave it away: every name answering with one address
    // is interception, whatever comes back over HTTP.
    let hijacked_dns = every_name_one_address;

    match reply {
        Ok(reply) => {
            if let Some(location) = redirect_target(reply) {
                return Verdict {
                    reached: true,
                    state: ReachabilityState::CaptivePortal,
                    login_url: Some(location),
                };
            }
            if reply.status == 204 && reply.body.trim().is_empty() {
                return online(hijacked_dns);
            }
            if reply.status == 200 && reply.body.contains(EXPECTED) {
                return online(hijacked_dns);
            }
            // Something answered on that URL and it was not the page. With no
            // Location header the request URL is the best guess we have.
            Verdict {
                reached: true,
                state: ReachabilityState::CaptivePortal,
                login_url: Some(PROBE_URL.to_owned()),
            }
        }
        // DNS worked and the connection did not: some networks block port 80
        // without running a portal. The internet is reachable; the web is not.
        Err(_) => Verdict {
            reached: false,
            state: if hijacked_dns {
                ReachabilityState::CaptivePortal
            } else {
                ReachabilityState::Online
            },
            login_url: None,
        },
    }
}

fn online(hijacked_dns: bool) -> Verdict {
    if hijacked_dns {
        return Verdict {
            reached: true,
            state: ReachabilityState::CaptivePortal,
            login_url: None,
        };
    }
    Verdict {
        reached: true,
        state: ReachabilityState::Online,
        login_url: None,
    }
}

fn redirect_target(reply: &HttpReply) -> Option<String> {
    if (300..400).contains(&reply.status) {
        return reply.location.clone().filter(|l| !l.is_empty());
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reply(status: u16, body: &str, location: Option<&str>) -> HttpReply {
        HttpReply {
            status,
            location: location.map(str::to_owned),
            body: body.to_owned(),
        }
    }

    #[test]
    fn no_content_is_online() {
        let reply = reply(204, "", None);
        assert_eq!(classify(Ok(&reply), false).state, ReachabilityState::Online);
    }

    #[test]
    fn apples_page_is_online() {
        let reply = reply(
            200,
            "<HTML><HEAD><TITLE>Success</TITLE></HEAD><BODY>Success</BODY></HTML>",
            None,
        );
        assert_eq!(classify(Ok(&reply), false).state, ReachabilityState::Online);
    }

    #[test]
    fn a_redirect_names_the_login_page() {
        let reply = reply(302, "", Some("http://wifi.example.net/login"));
        let verdict = classify(Ok(&reply), false);
        assert_eq!(verdict.state, ReachabilityState::CaptivePortal);
        assert_eq!(verdict.login_url.unwrap(), "http://wifi.example.net/login");
    }

    #[test]
    fn a_redirect_without_a_location_is_still_a_portal() {
        // Something intercepted the request; it just did not say where to go.
        let reply = reply(302, "", None);
        let verdict = classify(Ok(&reply), false);
        assert_eq!(verdict.state, ReachabilityState::CaptivePortal);
        assert_eq!(verdict.login_url.unwrap(), PROBE_URL);
    }

    #[test]
    fn someone_elses_page_is_a_portal() {
        let reply = reply(200, "<html>Please sign in to continue</html>", None);
        assert_eq!(
            classify(Ok(&reply), false).state,
            ReachabilityState::CaptivePortal
        );
    }

    #[test]
    fn a_refused_connection_after_working_dns_is_online_but_filtered() {
        let error = ProbeError::Failed("connection refused".to_owned());
        let verdict = classify(Err(&error), false);
        assert_eq!(verdict.state, ReachabilityState::Online);
        assert!(!verdict.reached, "the stage did not complete");
        assert!(verdict.login_url.is_none());
    }

    #[test]
    fn hijacked_dns_overrides_a_clean_http_answer() {
        // A portal that lets the detector through but answers every name with
        // one address is still a portal.
        let reply = reply(204, "", None);
        assert_eq!(
            classify(Ok(&reply), true).state,
            ReachabilityState::CaptivePortal
        );
        let error = ProbeError::Timeout;
        assert_eq!(
            classify(Err(&error), true).state,
            ReachabilityState::CaptivePortal
        );
    }
}
