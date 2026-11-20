//! Conservative lexical preview: locate standalone unsafe tokens outside comments/literals.
//! Not a parser, effect checker, or borrow checker.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub line: usize,
    pub column: usize,
    pub code: &'static str,
}

fn is_ident(ch: char) -> bool {
    ch == '_' || ch.is_alphanumeric()
}

fn skip_ident(source: &str, mut i: usize) -> usize {
    while i < source.len() {
        let ch = source[i..].chars().next().unwrap();
        if !is_ident(ch) {
            break;
        }
        i += ch.len_utf8();
    }
    i
}

fn position(source: &str, start: usize) -> (usize, usize) {
    let before = &source[..start];
    let line = before.bytes().filter(|b| *b == b'\n').count() + 1;
    let column = before.rsplit('\n').next().unwrap_or("").chars().count() + 1;
    (line, column)
}

pub fn scan_unsafe(source: &str) -> Vec<Finding> {
    let data = source.as_bytes();
    let mut i = 0;
    let mut found = Vec::new();

    while i < data.len() {
        if i + 1 < data.len() && data[i] == b'/' && data[i + 1] == b'/' {
            i += 2;
            while i < data.len() && data[i] != b'\n' { i += 1; }
            continue;
        }
        if i + 1 < data.len() && data[i] == b'/' && data[i + 1] == b'*' {
            i += 2;
            let mut depth = 1usize;
            while i < data.len() && depth > 0 {
                if i + 1 < data.len() && data[i] == b'/' && data[i + 1] == b'*' {
                    depth += 1;
                    i += 2;
                } else if i + 1 < data.len() && data[i] == b'*' && data[i + 1] == b'/' {
                    depth -= 1;
                    i += 2;
                } else {
                    i += 1;
                }
            }
            continue;
        }
        if data[i] == b'"' || data[i] == b'\'' || data[i] == b'\x60' {
            let delim = data[i];
            i += 1;
            while i < data.len() {
                if data[i] == b'\\' {
                    i = (i + 2).min(data.len());
                } else if data[i] == delim {
                    i += 1;
                    break;
                } else {
                    i += 1;
                }
            }
            continue;
        }
        if data[i] == b'#' {
            i += 1;
            if i < data.len() {
                let ch = source[i..].chars().next().unwrap();
                if ch == '_' || ch.is_alphabetic() {
                    i = skip_ident(source, i);
                }
            }
            continue;
        }
        let ch = source[i..].chars().next().unwrap();
        if ch == '_' || ch.is_alphabetic() {
            let start = i;
            i = skip_ident(source, i);
            if &source[start..i] == "unsafe" {
                let (line, column) = position(source, start);
                found.push(Finding { line, column, code: "ATTO001" });
            }
        } else {
            i += ch.len_utf8();
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_standalone_tokens_with_unicode_columns() {
        let findings = scan_unsafe("α unsafe;\n  unsafe\nunsafe_extra; αunsafe");
        assert_eq!(findings, vec![
            Finding { line: 1, column: 3, code: "ATTO001" },
            Finding { line: 2, column: 3, code: "ATTO001" },
        ]);
    }

    #[test]
    fn masks_comments_quotes_symbols_and_nested_blocks() {
        let source = r##"// unsafe
/* outer unsafe /* nested unsafe */ still unsafe */
"unsafe" 'unsafe' #unsafe #"unsafe" `unsafe`
unsafe;
"##;
        assert_eq!(scan_unsafe(source),
                   vec![Finding { line: 4, column: 1, code: "ATTO001" }]);
    }

    #[test]
    fn escapes_do_not_end_literals_prematurely() {
        assert!(scan_unsafe(r#""escaped \" unsafe" /* unsafe */"#).is_empty());
    }
}
