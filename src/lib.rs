//! Bounded, dependency-free source admission for static analysis.
//! This lexer checks only malformed lexical containers, not AttoLang grammar.

pub const MAX_SOURCE_BYTES: usize = 1024 * 1024;
pub const MAX_COMMENT_DEPTH: usize = 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    SourceTooLarge,
    NulByte,
    UnterminatedBlockComment,
    BlockCommentTooDeep,
    UnterminatedLiteral,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Diagnostic {
    pub kind: Kind,
    /// Zero-based byte offset, not a Unicode scalar or UTF-16 offset.
    pub byte_offset: usize,
    /// One-based line and byte-column in the original source.
    pub line: usize,
    pub byte_column: usize,
}

fn diagnostic(source: &str, byte_offset: usize, kind: Kind) -> Diagnostic {
    let prefix = &source.as_bytes()[..byte_offset.min(source.len())];
    let line = 1 + prefix.iter().filter(|&&b| b == b'\n').count();
    let byte_column = prefix.iter().rposition(|&b| b == b'\n')
        .map_or(prefix.len() + 1, |last_newline| prefix.len() - last_newline);
    Diagnostic { kind, byte_offset, line, byte_column }
}

/// Rejects oversized input, NUL and unterminated literal/comment spans without
/// executing input or claiming to implement the AttoLang grammar.
/// Single/double quotes and template ` are opaque lexical containers;
/// expression interpolation and type checking are not performed.
pub fn preflight(source: &str) -> Result<(), Diagnostic> {
    if source.len() > MAX_SOURCE_BYTES {
        return Err(diagnostic(source, MAX_SOURCE_BYTES, Kind::SourceTooLarge));
    }
    let b = source.as_bytes();
    if let Some(offset) = b.iter().position(|&v| v == 0) {
        return Err(diagnostic(source, offset, Kind::NulByte));
    }
    let mut i = 0;
    while i < b.len() {
        if b[i..].starts_with(b"//") {
            i += 2;
            while i < b.len() && b[i] != b'\n' { i += 1; }
        } else if b[i..].starts_with(b"/*") {
            let start = i;
            let mut depth = 1_usize;
            i += 2;
            while i < b.len() && depth > 0 {
                if b[i..].starts_with(b"/*") {
                    if depth == MAX_COMMENT_DEPTH {
                        return Err(diagnostic(source, i, Kind::BlockCommentTooDeep));
                    }
                    depth += 1;
                    i += 2;
                } else if b[i..].starts_with(b"*/") {
                    depth -= 1;
                    i += 2;
                } else { i += 1; }
            }
            if depth != 0 {
                return Err(diagnostic(source, start, Kind::UnterminatedBlockComment));
            }
        } else if matches!(b[i], b'\'' | b'"' | b'`') {
            let quote = b[i];
            let start = i;
            i += 1;
            let mut closed = false;
            while i < b.len() {
                if b[i] == b'\\' {
                    i = (i + 2).min(b.len());
                } else if b[i] == quote {
                    i += 1;
                    closed = true;
                    break;
                } else { i += 1; }
            }
            if !closed { return Err(diagnostic(source, start, Kind::UnterminatedLiteral)); }
        } else { i += 1; }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ordinary_atto_sources_are_admitted_without_claiming_to_parse_them() {
        for input in [
            "pub pure fnc main(): int { return 5; }",
            "mtd (self: Counter) foo() -> int :: 5 end",
            "/* before /* nested */ after */ val x = \"/* not a comment */\";",
            "// /* only comment\nval z = `raw // and /*`",
            "#\"symbol with spaces\"",
        ] { assert_eq!(preflight(input), Ok(()), "{input}"); }
    }
    #[test]
    fn rejects_invalid_containers_with_byte_accurate_locations() {
        let d = preflight("é\n/* outer /* inner */").unwrap_err();
        assert_eq!(d, Diagnostic {kind:Kind::UnterminatedBlockComment, byte_offset:3,line:2,byte_column:1});
        assert_eq!(preflight("val x = \"not closed").unwrap_err().kind, Kind::UnterminatedLiteral);
        assert_eq!(preflight("val x = '\\\'';"), Ok(()));
        assert_eq!(preflight("abc\0def").unwrap_err().byte_offset, 3);
        assert_eq!(preflight("// ignored\0still rejected").unwrap_err().kind, Kind::NulByte);
        assert_eq!(preflight("\"escaped \\\0\"").unwrap_err().kind, Kind::NulByte);
    }
    #[test]
    fn limits_file_size_and_nested_comment_depth() {
        let input = "x".repeat(MAX_SOURCE_BYTES + 1);
        assert_eq!(preflight(&input).unwrap_err().kind, Kind::SourceTooLarge);
        let text = format!("{}{}", "/*".repeat(MAX_COMMENT_DEPTH + 1), "*/".repeat(MAX_COMMENT_DEPTH + 1));
        assert_eq!(preflight(&text).unwrap_err().kind, Kind::BlockCommentTooDeep);
    }
}
