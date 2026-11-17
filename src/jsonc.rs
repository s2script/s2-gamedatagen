//! A JSONC reader that remembers where every value sits in the source, so a regenerated value can
//! be written back in place with every comment and the original formatting kept.

use anyhow::{Result, bail};
use serde_json::{Map, Number, Value};
use std::collections::HashMap;

pub struct Doc {
    pub src: String,
    pub value: Value,
    /// "/"-joined path -> byte span of the value
    pub spans: HashMap<String, (usize, usize)>,
}

struct P<'a> {
    s: &'a [u8],
    i: usize,
    spans: HashMap<String, (usize, usize)>,
}

impl<'a> P<'a> {
    fn ws(&mut self) {
        loop {
            while self.i < self.s.len() && (self.s[self.i] as char).is_ascii_whitespace() {
                self.i += 1;
            }
            if self.s[self.i..].starts_with(b"//") {
                while self.i < self.s.len() && self.s[self.i] != b'\n' {
                    self.i += 1;
                }
            } else if self.s[self.i..].starts_with(b"/*") {
                self.i += 2;
                while self.i + 1 < self.s.len() && !self.s[self.i..].starts_with(b"*/") {
                    self.i += 1;
                }
                self.i += 2;
            } else {
                break;
            }
        }
    }

    fn value(&mut self, path: &str) -> Result<Value> {
        self.ws();
        let start = self.i;
        let v = match self.s.get(self.i) {
            Some(b'{') => {
                self.i += 1;
                let mut m = Map::new();
                loop {
                    self.ws();
                    if self.s[self.i] == b'}' {
                        self.i += 1;
                        break;
                    }
                    let k = self.string()?;
                    self.ws();
                    if self.s[self.i] != b':' {
                        bail!("expected ':' at byte {}", self.i);
                    }
                    self.i += 1;
                    let v = self.value(&format!("{path}/{k}"))?;
                    m.insert(k, v);
                    self.ws();
                    match self.s[self.i] {
                        b',' => self.i += 1,
                        b'}' => {}
                        c => bail!("expected ',' or '}}' at byte {}, got {:?}", self.i, c as char),
                    }
                }
                Value::Object(m)
            }
            Some(b'[') => {
                self.i += 1;
                let mut a = Vec::new();
                loop {
                    self.ws();
                    if self.s[self.i] == b']' {
                        self.i += 1;
                        break;
                    }
                    let v = self.value(&format!("{path}/{}", a.len()))?;
                    a.push(v);
                    self.ws();
                    match self.s[self.i] {
                        b',' => self.i += 1,
                        b']' => {}
                        c => bail!("expected ',' or ']' at byte {}, got {:?}", self.i, c as char),
                    }
                }
                Value::Array(a)
            }
            Some(b'"') => Value::String(self.string()?),
            Some(_) => {
                let st = self.i;
                while self.i < self.s.len() && !b",}] \t\r\n/".contains(&self.s[self.i]) {
                    self.i += 1;
                }
                let tok = std::str::from_utf8(&self.s[st..self.i])?;
                match tok {
                    "true" => Value::Bool(true),
                    "false" => Value::Bool(false),
                    "null" => Value::Null,
                    _ => {
                        let n: Number = serde_json::from_str(tok).map_err(|e| anyhow::anyhow!("bad number {tok:?}: {e}"))?;
                        Value::Number(n)
                    }
                }
            }
            None => bail!("unexpected end"),
        };
        self.spans.insert(path.to_string(), (start, self.i));
        Ok(v)
    }

    fn string(&mut self) -> Result<String> {
        if self.s[self.i] != b'"' {
            bail!("expected string at byte {}", self.i);
        }
        let st = self.i;
        self.i += 1;
        while self.s[self.i] != b'"' {
            if self.s[self.i] == b'\\' {
                self.i += 1;
            }
            self.i += 1;
        }
        self.i += 1;
        Ok(serde_json::from_slice(&self.s[st..self.i])?)
    }
}

impl Doc {
    pub fn parse(src: String) -> Result<Doc> {
        let mut p = P { s: src.as_bytes(), i: 0, spans: HashMap::new() };
        let value = p.value("")?;
        let spans = p.spans;
        Ok(Doc { src, value, spans })
    }
}

/// Pending in-place replacements for one document.
#[derive(Default)]
pub struct Edits {
    edits: Vec<(usize, usize, String)>,
}

impl Edits {
    pub fn set(&mut self, doc: &Doc, path: &str, v: &Value) -> Result<()> {
        let Some(&(a, b)) = doc.spans.get(path) else { bail!("no value at {path}") };
        self.edits.retain(|e| e.0 != a);
        self.edits.push((a, b, serde_json::to_string(v)?));
        Ok(())
    }

    pub fn is_empty(&self) -> bool {
        self.edits.is_empty()
    }

    pub fn apply(&self, src: &str) -> String {
        let mut e = self.edits.clone();
        e.sort_by_key(|x| std::cmp::Reverse(x.0));
        let mut out = src.to_string();
        for (a, b, s) in e {
            out.replace_range(a..b, &s);
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SRC: &str = r#"// header comment
{
  "signatures": {
    // a comment with "quotes" and { braces }
    "A": { "linuxsteamrt64": { "pattern": "55 48 ?", "validate": { "string-xref": { "at": 12 } } } }
  },
  /* block */ "offsets": { "X_vtableSize": { "linuxsteamrt64": 22 }, "url": "http://x//y" }
}
"#;

    #[test]
    fn parses_comments_and_keeps_spans() {
        let d = Doc::parse(SRC.into()).unwrap();
        assert_eq!(d.value["offsets"]["url"], "http://x//y");
        let (a, b) = d.spans["/offsets/X_vtableSize/linuxsteamrt64"];
        assert_eq!(&SRC[a..b], "22");
    }

    #[test]
    fn edits_in_place() {
        let d = Doc::parse(SRC.into()).unwrap();
        let mut e = Edits::default();
        e.set(&d, "/offsets/X_vtableSize/linuxsteamrt64", &serde_json::json!(19)).unwrap();
        e.set(&d, "/signatures/A/linuxsteamrt64/pattern", &serde_json::json!("55 ? C3")).unwrap();
        e.set(&d, "/signatures/A/linuxsteamrt64/validate/string-xref/at", &serde_json::json!(7)).unwrap();
        let out = e.apply(SRC);
        assert!(out.contains("// a comment with \"quotes\" and { braces }"));
        assert!(out.contains(r#""linuxsteamrt64": 19 }"#));
        assert!(out.contains(r#""pattern": "55 ? C3""#));
        assert!(out.contains(r#""at": 7 }"#));
        let d2 = Doc::parse(out).unwrap();
        assert_eq!(d2.value["offsets"]["X_vtableSize"]["linuxsteamrt64"], 19);
    }
}
