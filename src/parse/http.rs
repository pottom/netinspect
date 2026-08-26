//! An HTTP/1.1 response reader, for talking to a container runtime over its
//! own unix socket.
//!
//! Not a general client. It reads exactly what a local daemon on the other end
//! of a unix socket replies to one `GET`: a status line, headers, and a body
//! that is either `Content-Length`-delimited, chunked, or simply everything
//! until the peer closes. `reqwest` cannot be pointed at a unix socket without
//! building a custom connector, and that is a great deal of machinery for one
//! request against a socket on this machine.
//!
//! Pure, like everything else in this module: the socket is somewhere else, so
//! every malformed reply a daemon could produce is reachable from a test.

/// What a response says, once the framing is stripped off.
#[derive(Debug, PartialEq, Eq)]
pub struct Response<'a> {
    pub status: u16,
    pub body: Vec<u8>,
    /// Retained so a caller can tell a truncated read from an empty body.
    pub complete: bool,
    /// Borrowed from the input so this stays allocation-light on the happy path
    /// where the body is not chunked.
    pub reason: &'a str,
}

/// Read a whole response out of a buffer.
///
/// Returns `None` for anything that is not recognisably an HTTP/1.x response —
/// a daemon that answers something else is a daemon we do not understand, and
/// guessing at its meaning is worse than reporting nothing.
pub fn response(buffer: &[u8]) -> Option<Response<'_>> {
    let (head, rest) = split_head(buffer)?;
    let head = std::str::from_utf8(head).ok()?;
    let mut lines = head.split("\r\n");

    let status_line = lines.next()?;
    let mut parts = status_line.splitn(3, ' ');
    let version = parts.next()?;
    if !version.starts_with("HTTP/1.") {
        return None;
    }
    let status: u16 = parts.next()?.parse().ok()?;
    let reason = parts.next().unwrap_or("").trim();

    let mut length: Option<usize> = None;
    let mut chunked = false;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim();
        // Header names are case-insensitive and daemons disagree about the
        // casing, so compare folded.
        if name.eq_ignore_ascii_case("content-length") {
            length = value.parse().ok();
        } else if name.eq_ignore_ascii_case("transfer-encoding")
            && value.eq_ignore_ascii_case("chunked")
        {
            chunked = true;
        }
    }

    // Chunked wins: a reply carrying both is framed by the encoding, and the
    // length is the one to ignore.
    let (body, complete) = if chunked {
        dechunk(rest)
    } else if let Some(length) = length {
        if rest.len() >= length {
            (rest[..length].to_vec(), true)
        } else {
            (rest.to_vec(), false)
        }
    } else {
        // No framing at all means the body ran to the close of the connection,
        // which is exactly what we asked for with `Connection: close`.
        (rest.to_vec(), true)
    };

    Some(Response {
        status,
        body,
        complete,
        reason,
    })
}

/// Split the head from the body at the blank line, tolerating a reply that
/// ends there.
fn split_head(buffer: &[u8]) -> Option<(&[u8], &[u8])> {
    let at = buffer.windows(4).position(|w| w == b"\r\n\r\n")?;
    Some((&buffer[..at], &buffer[at + 4..]))
}

/// Reassemble a chunked body.
///
/// A short read stops at the last whole chunk and says so rather than
/// returning a body that silently ends mid-object.
fn dechunk(mut rest: &[u8]) -> (Vec<u8>, bool) {
    let mut body = Vec::new();
    loop {
        let Some(at) = rest.windows(2).position(|w| w == b"\r\n") else {
            return (body, false);
        };
        // A chunk size may carry extensions after a semicolon; they are not
        // ours to interpret.
        let header = &rest[..at];
        let digits = header.split(|b| *b == b';').next().unwrap_or(header);
        let Ok(text) = std::str::from_utf8(digits) else {
            return (body, false);
        };
        let Ok(size) = usize::from_str_radix(text.trim(), 16) else {
            return (body, false);
        };
        rest = &rest[at + 2..];
        if size == 0 {
            return (body, true);
        }
        if rest.len() < size {
            return (body, false);
        }
        body.extend_from_slice(&rest[..size]);
        // Skip the chunk's own trailing CRLF, if the peer got that far.
        rest = rest.get(size + 2..).unwrap_or(&[]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_content_length_body_is_read_exactly() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n[]trailing";
        let response = response(raw).unwrap();
        assert_eq!(response.status, 200);
        assert_eq!(response.body, b"[]");
        assert!(response.complete);
    }

    #[test]
    fn a_chunked_body_is_reassembled() {
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\n[1,\r\n2\r\n2]\r\n0\r\n\r\n";
        let response = response(raw).unwrap();
        assert_eq!(response.body, b"[1,2]");
        assert!(response.complete);
    }

    /// Header names arrive in whatever casing the daemon feels like.
    #[test]
    fn header_names_are_matched_without_regard_to_case() {
        let raw = b"HTTP/1.1 200 OK\r\ntransfer-encoding: Chunked\r\n\r\n2\r\n[]\r\n0\r\n\r\n";
        assert_eq!(response(raw).unwrap().body, b"[]");
    }

    /// The framing header wins over a length that contradicts it.
    #[test]
    fn chunked_framing_beats_a_content_length_that_disagrees() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 99\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n[]\r\n0\r\n\r\n";
        let response = response(raw).unwrap();
        assert_eq!(response.body, b"[]");
        assert!(response.complete);
    }

    /// Without either header the body runs to the close, which is what
    /// `Connection: close` asks for.
    #[test]
    fn an_unframed_body_runs_to_the_end_of_the_buffer() {
        let raw = b"HTTP/1.1 200 OK\r\n\r\n[{}]";
        let response = response(raw).unwrap();
        assert_eq!(response.body, b"[{}]");
        assert!(response.complete);
    }

    /// A body cut off mid-flight must be reported as incomplete, never handed
    /// on as if it were the whole answer.
    #[test]
    fn a_truncated_body_is_marked_incomplete() {
        let short = response(b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\n\r\n[1,2").unwrap();
        assert!(!short.complete);

        let cut =
            response(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n8\r\n[1,").unwrap();
        assert!(!cut.complete);
        assert!(cut.body.is_empty(), "a partial chunk is not a body");
    }

    #[test]
    fn an_error_status_is_reported_rather_than_hidden() {
        let raw = b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n";
        let response = response(raw).unwrap();
        assert_eq!(response.status, 403);
        assert_eq!(response.reason, "Forbidden");
    }

    #[test]
    fn something_that_is_not_http_is_refused_rather_than_guessed_at() {
        assert!(response(b"").is_none());
        assert!(response(b"not http at all\r\n\r\n").is_none());
        assert!(response(b"HTTP/2 200\r\n\r\n").is_none());
        // A head that never terminates is not a response yet.
        assert!(response(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n").is_none());
    }

    /// Chunk extensions are legal and none of our business.
    #[test]
    fn a_chunk_extension_does_not_derail_the_size() {
        let raw =
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2;name=value\r\n[]\r\n0\r\n\r\n";
        assert_eq!(response(raw).unwrap().body, b"[]");
    }
}
