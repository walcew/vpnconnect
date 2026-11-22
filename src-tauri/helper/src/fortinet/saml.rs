//! O que o listener do login pelo navegador aceita no SAML do Fortinet: o `id` que o gateway
//! manda o navegador entregar em `127.0.0.1:<sso_port>`.

/// O formato do `id` é **inf**: aceita o que cabe numa query sem escape, com folga no tamanho.
const MAX_ID: usize = 1024;

/// O `id` de uma linha `GET /?id=<id> HTTP/1.x`: até o primeiro `&`, só com caracteres de URL sem escape especial.
pub fn extract_id(request_line: &str) -> Option<String> {
    let target = request_line.strip_prefix("GET ")?.split(' ').next()?;
    let id = target.strip_prefix("/?id=")?.split('&').next()?;
    let valid = !id.is_empty()
        && id.len() <= MAX_ID
        && id.bytes().all(|b| b.is_ascii_alphanumeric() || b"-_.~%".contains(&b));
    valid.then(|| id.to_string())
}
