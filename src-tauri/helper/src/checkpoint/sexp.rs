//! S-expression do Check Point, no canal de controle e nos quadros de controle do túnel, e a
//! ofuscação dos valores secretos. O formato está em `docs/checkpoint-protocol.md`.

/// Um nó: valor, objeto (com nome opcional e campos em ordem) ou lista.
#[derive(Debug, Clone, PartialEq)]
pub enum Sexp {
    /// `()` vira valor vazio, que também serve de objeto ou lista vazia.
    Value(String),
    Object(Option<String>, Vec<(String, Sexp)>),
    Array(Vec<Sexp>),
}

impl Sexp {
    pub fn val(v: impl Into<String>) -> Self {
        Sexp::Value(v.into())
    }

    /// Objeto com nome (`name` vazio = sem nome).
    pub fn obj(name: &str, fields: Vec<(&str, Sexp)>) -> Self {
        let name = (!name.is_empty()).then(|| name.to_string());
        Sexp::Object(name, fields.into_iter().map(|(k, v)| (k.to_string(), v)).collect())
    }

    /// Nome do objeto de topo (`CCCserverResponse`, `hello_reply`...).
    pub fn name(&self) -> Option<&str> {
        match self {
            Sexp::Object(name, _) => name.as_deref(),
            _ => None,
        }
    }

    /// Nó por caminho `a:b:c` a partir deste (sem o nome dele); índice numérico entra em lista.
    pub fn get(&self, path: &str) -> Option<&Sexp> {
        path.split(':').try_fold(self, |node, key| match node {
            Sexp::Object(_, fields) => fields.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            Sexp::Array(items) => items.get(key.parse::<usize>().ok()?),
            Sexp::Value(_) => None,
        })
    }

    /// Texto de um valor por caminho.
    pub fn text(&self, path: &str) -> Option<&str> {
        match self.get(path)? {
            Sexp::Value(v) => Some(v),
            _ => None,
        }
    }

    /// Filhos de uma lista ou valores dos campos de um objeto (listas que o gateway manda como
    /// objeto de chaves `0`, `1`...); vazio para um valor.
    pub fn children(&self) -> Vec<&Sexp> {
        match self {
            Sexp::Array(items) => items.iter().collect(),
            Sexp::Object(_, fields) => fields.iter().map(|(_, v)| v).collect(),
            Sexp::Value(_) => Vec::new(),
        }
    }

    /// Texto no layout do protocolo: um campo por linha, recuado com tab.
    pub fn encode(&self) -> String {
        let mut out = String::new();
        self.write(0, &mut out);
        out
    }

    fn write(&self, level: usize, out: &mut String) {
        let indent = "\t".repeat(level + 1);
        out.push('(');
        match self {
            Sexp::Value(v) => out.push_str(&quote(v)),
            Sexp::Object(name, fields) => {
                out.push_str(&quote(name.as_deref().unwrap_or_default()));
                for (k, v) in fields {
                    out.push_str(&format!("\n{}:{} ", indent, k));
                    v.write(level + 1, out);
                }
            }
            Sexp::Array(items) => {
                for v in items {
                    out.push_str(&format!("\n{}: ", indent));
                    v.write(level + 1, out);
                }
            }
        }
        out.push(')');
    }
}

/// Entre aspas quando tem algo fora de letras, dígitos, `_`, `-` e `.`.
fn quote(v: &str) -> String {
    if v.bytes().all(|b| b.is_ascii_alphanumeric() || b"_-.".contains(&b)) {
        v.to_string()
    } else {
        format!("\"{}\"", v)
    }
}

/// Lê uma S-expression inteira; o NUL que fecha um quadro de controle conta como espaço.
pub fn parse(text: &str) -> Result<Sexp, String> {
    let mut p = Parser { s: text.as_bytes(), i: 0 };
    let node = p.node()?;
    p.skip_ws();
    if p.i != p.s.len() {
        return Err(format!("trailing data at byte {}", p.i));
    }
    Ok(node)
}

struct Parser<'a> {
    s: &'a [u8],
    i: usize,
}

impl Parser<'_> {
    fn peek(&self) -> Option<u8> {
        self.s.get(self.i).copied()
    }

    fn skip_ws(&mut self) {
        while self.peek().is_some_and(|b| b" \t\r\n\0".contains(&b)) {
            self.i += 1;
        }
    }

    fn expect(&mut self, b: u8) -> Result<(), String> {
        self.skip_ws();
        if self.peek() != Some(b) {
            return Err(format!("expected '{}' at byte {}", b as char, self.i));
        }
        self.i += 1;
        Ok(())
    }

    /// `(` conteúdo `)`.
    fn node(&mut self) -> Result<Sexp, String> {
        self.expect(b'(')?;
        self.skip_ws();
        let name = match self.peek() {
            Some(b':') | Some(b')') => None,
            Some(b'"') => Some(self.quoted()?),
            _ => Some(self.word()),
        };
        self.skip_ws();
        let node = match (self.peek(), name) {
            (Some(b')'), name) => Sexp::Value(name.unwrap_or_default()),
            (Some(b':'), name) => self.members(name)?,
            // Valor com espaços, sem aspas: vai até o `)`.
            (_, Some(start)) => {
                let rest = self.until_close();
                Sexp::Value(format!("{} {}", start, rest).trim().to_string())
            }
            _ => return Err("unexpected end".into()),
        };
        self.expect(b')')?;
        Ok(node)
    }

    /// Campos `:nome (...)` de um objeto ou itens `: (...)` de uma lista.
    fn members(&mut self, name: Option<String>) -> Result<Sexp, String> {
        let mut fields = Vec::new();
        let mut items = Vec::new();
        while self.peek() == Some(b':') {
            self.i += 1;
            if matches!(self.peek(), Some(b'(') | Some(b' ') | Some(b'\t') | Some(b'\r') | Some(b'\n')) {
                items.push(self.node()?);
            } else {
                let key = self.word();
                fields.push((key, self.node()?));
            }
            self.skip_ws();
        }
        match (fields.is_empty(), items.is_empty()) {
            (_, true) => Ok(Sexp::Object(name, fields)),
            (true, false) if name.is_none() => Ok(Sexp::Array(items)),
            _ => Err(format!("mixed fields and items before byte {}", self.i)),
        }
    }

    /// Nome ou valor simples: até espaço ou parêntese.
    fn word(&mut self) -> String {
        let start = self.i;
        while self.peek().is_some_and(|b| !b" \t\r\n\0()".contains(&b)) {
            self.i += 1;
        }
        String::from_utf8_lossy(&self.s[start..self.i]).into_owned()
    }

    /// `"..."`, sem escapes (o protocolo não os usa).
    fn quoted(&mut self) -> Result<String, String> {
        self.i += 1;
        let start = self.i;
        while self.peek().is_some_and(|b| b != b'"') {
            self.i += 1;
        }
        if self.peek().is_none() {
            return Err("unterminated quoted value".into());
        }
        self.i += 1;
        Ok(String::from_utf8_lossy(&self.s[start..self.i - 1]).into_owned())
    }

    fn until_close(&mut self) -> String {
        let start = self.i;
        while self.peek().is_some_and(|b| b != b')' && b != b'(') {
            self.i += 1;
        }
        String::from_utf8_lossy(&self.s[start..self.i]).trim().to_string()
    }
}

/// Chave fixa da ofuscação, aplicada por posição e repetida a cada 77 bytes.
const KEY: &[u8; 77] = b"-ODIFIED&W0ROPERTY3HEET7ITH/+4HE3HEET)$3?,$!0?!5?02/0%24)%3.5,,\x10&7?70?/\"*%#43";

/// XOR de um byte com a chave da sua posição; o 0 resultante vira 255, e 255 de entrada conta
/// como 0. Aplicada duas vezes, devolve qualquer byte ASCII de 1 a 127 (a chave é ASCII).
fn mask(i: usize, b: u8) -> u8 {
    match (b % 255) ^ KEY[i % KEY.len()] {
        0 => 255,
        v => v,
    }
}

/// Ofusca um valor secreto: máscara por posição, bytes em ordem inversa, hex minúsculo.
pub fn obfuscate(data: &[u8]) -> String {
    data.iter().enumerate().rev().map(|(i, b)| format!("{:02x}", mask(i, *b))).collect()
}

/// Inverso do `obfuscate`.
pub fn deobfuscate(hex: &str) -> Result<Vec<u8>, String> {
    if !hex.len().is_multiple_of(2) || !hex.is_ascii() {
        return Err("obfuscated value is not hex".into());
    }
    let mut bytes = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).map_err(|_| "obfuscated value is not hex".to_string()))
        .collect::<Result<Vec<u8>, String>>()?;
    bytes.reverse();
    Ok(bytes.iter().enumerate().map(|(i, b)| mask(i, *b)).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Amostras de `docs/checkpoint-protocol.md`.
    #[test]
    fn obfuscation_matches_the_protocol_doc_samples() {
        assert_eq!(obfuscate(b"vpnconnect"), "2345212b27292a2a3f5b");
        assert_eq!(obfuscate(b""), "");
        assert_eq!(deobfuscate("2345212b27292a2a3f5b").unwrap(), b"vpnconnect");
    }

    #[test]
    fn obfuscation_round_trips_ascii_and_wraps_the_key() {
        // Fora do ASCII (e no NUL) dois bytes podem sair como o mesmo 255; ver a doc.
        let data: Vec<u8> = (1..=127u8).chain(1..=127u8).collect();
        assert_eq!(deobfuscate(&obfuscate(&data)).unwrap(), data);
        // Um byte igual à chave da posição sai como 255, nunca como 0.
        assert_eq!(obfuscate(b"-"), "ff");
        assert!(deobfuscate("abc").is_err());
        assert!(deobfuscate("zz").is_err());
    }

    #[test]
    fn reads_the_server_response_sample_of_the_doc() {
        let text = "(CCCserverResponse\n\t:ResponseHeader (\n\t\t:id (2)\n\t\t:type (UserPass)\n\t\t:session_id ()\n\t\t:return_code (600))\n\
                    \t:ResponseData (\n\t\t:authn_status (continue)\n\t\t:prompt (1e75)\n\t\t:message (\"Hello world\")\n\
                    \t\t:servers (\n\t\t\t: (10.0.0.1)\n\t\t\t: (10.0.0.2))\n\t\t:free (text here)))\0";
        let s = parse(text).unwrap();
        assert_eq!(s.name(), Some("CCCserverResponse"));
        assert_eq!(s.text("ResponseHeader:return_code"), Some("600"));
        assert_eq!(s.text("ResponseHeader:session_id"), Some(""));
        assert_eq!(s.text("ResponseData:message"), Some("Hello world"));
        assert_eq!(s.text("ResponseData:servers:1"), Some("10.0.0.2"));
        assert_eq!(s.text("ResponseData:free"), Some("text here"));
        assert_eq!(s.get("ResponseData:servers").unwrap().children().len(), 2);
        assert_eq!(s.get("ResponseData:missing"), None);
    }

    #[test]
    fn reads_lists_sent_as_numbered_objects() {
        let s = parse("(:list (:0 (:id (a)) :1 (:id (b))))").unwrap();
        let ids: Vec<_> = s.get("list").unwrap().children().iter().filter_map(|o| o.text("id")).collect();
        assert_eq!(ids, ["a", "b"]);
    }

    #[test]
    fn refuses_malformed_input() {
        for bad in ["", "(", "(a :b (c)", "(:a (b)) x", "(\"open)", "(: (a) :b (c))"] {
            assert!(parse(bad).is_err(), "{:?}", bad);
        }
    }

    #[test]
    fn writes_the_client_request_layout_of_the_doc() {
        let req = Sexp::obj(
            "CCCclientRequest",
            vec![
                ("RequestHeader", Sexp::obj("", vec![("id", Sexp::val("1")), ("session_id", Sexp::val(""))])),
                ("RequestData", Sexp::obj("", vec![("client_name", Sexp::val("VPN Connect")), ("list", Sexp::Array(vec![Sexp::val("a")]))])),
            ],
        );
        let text = req.encode();
        assert_eq!(
            text,
            "(CCCclientRequest\n\t:RequestHeader (\n\t\t:id (1)\n\t\t:session_id ())\n\t:RequestData (\n\t\t:client_name (\"VPN Connect\")\n\t\t:list (\n\t\t\t: (a))))"
        );
        assert_eq!(parse(&text).unwrap(), req);
    }
}
