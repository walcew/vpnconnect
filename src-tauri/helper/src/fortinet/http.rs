//! O mínimo de HTTP/1.1 que o protocolo usa.

use tokio::io::{AsyncRead, AsyncReadExt};

/// Sem `Debug` de propósito: guarda o `Set-Cookie` com o cookie de sessão.
pub struct Response {
    pub status: u16,
    headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Response {
    /// Valor de um cookie em `Set-Cookie`.
    pub fn cookie(&self, name: &str) -> Option<String> {
        self.headers
            .iter()
            .filter(|(k, _)| k == "set-cookie")
            .filter_map(|(_, v)| v.split(';').next()?.trim().strip_prefix(name)?.strip_prefix('=').map(str::to_string))
            .next()
    }

    /// `nome=valor` de cada `Set-Cookie` com valor, juntos como no cabeçalho `Cookie`.
    pub fn cookies(&self) -> String {
        self.headers
            .iter()
            .filter(|(k, _)| k == "set-cookie")
            .filter_map(|(_, v)| v.split(';').next().map(str::trim))
            .filter(|c| c.split_once('=').is_some_and(|(_, v)| !v.is_empty()))
            .collect::<Vec<_>>()
            .join("; ")
    }

    fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str())
    }
}

/// Lê uma resposta inteira: por `Content-Length`, chunked ou até o EOF.
pub async fn read_response<S: AsyncRead + Unpin>(stream: &mut S) -> Result<Response, String> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        let n = match stream.read(&mut chunk).await {
            Ok(n) => n,
            // Gateways costumam fechar sem close_notify.
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => 0,
            Err(e) => return Err(e.to_string()),
        };
        buf.extend_from_slice(&chunk[..n]);
        if let Some(resp) = parse_response(&buf, n == 0)? {
            return Ok(resp);
        }
        if n == 0 {
            return Err("connection closed before the response ended".into());
        }
    }
}

/// None enquanto a resposta estiver incompleta.
fn parse_response(buf: &[u8], eof: bool) -> Result<Option<Response>, String> {
    let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") else {
        return Ok(None);
    };
    let head = String::from_utf8_lossy(&buf[..end]);
    let mut lines = head.split("\r\n");
    let status = lines
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse().ok())
        .ok_or("invalid HTTP status line")?;
    let headers = lines
        .filter_map(|l| l.split_once(':'))
        .map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_string()))
        .collect();
    let mut resp = Response { status, headers, body: Vec::new() };
    let rest = &buf[end + 4..];

    if let Some(len) = resp.header("content-length").and_then(|v| v.parse::<usize>().ok()) {
        if rest.len() < len {
            return Ok(None);
        }
        resp.body = rest[..len].to_vec();
    } else if resp.header("transfer-encoding").is_some_and(|v| v.eq_ignore_ascii_case("chunked")) {
        match dechunk(rest) {
            Some(body) => resp.body = body,
            None => return Ok(None),
        }
    } else if eof {
        resp.body = rest.to_vec();
    } else {
        return Ok(None);
    }
    Ok(Some(resp))
}

/// Corpo chunked completo, ou None se ainda faltar o chunk final.
fn dechunk(mut data: &[u8]) -> Option<Vec<u8>> {
    let mut body = Vec::new();
    loop {
        let line_end = data.windows(2).position(|w| w == b"\r\n")?;
        let size_text = std::str::from_utf8(&data[..line_end]).ok()?;
        let size = usize::from_str_radix(size_text.split(';').next()?.trim(), 16).ok()?;
        data = &data[line_end + 2..];
        if size == 0 {
            return Some(body);
        }
        if data.len() < size + 2 {
            return None;
        }
        body.extend_from_slice(&data[..size]);
        data = &data[size + 2..];
    }
}

/// `application/x-www-form-urlencoded` de um valor.
pub fn form_encode(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'*' => (b as char).to_string(),
            b' ' => "+".into(),
            _ => format!("%{:02X}", b),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chunked_body_is_decoded_only_when_complete() {
        let full = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nabcd\r\n2\r\nef\r\n0\r\n\r\n";
        assert!(parse_response(&full[..full.len() - 7], false).unwrap().is_none());
        assert_eq!(parse_response(full, false).unwrap().unwrap().body, b"abcdef");
    }
}
