//! 域名白名单：模式解析与匹配。
//!
//! 支持三种写法（大小写不敏感）：
//! - `example.com`     后缀匹配：自身 + 所有子域
//! - `*.example.com`   后缀匹配（同上，显式写法）
//! - `api.*` / `api.`  前缀匹配：以 `api.` 开头的域名

/// 单条模式
#[derive(Clone, Debug, PartialEq, Eq)]
enum Pattern {
    /// 后缀匹配：`value` 为域名后缀（不含前导点）
    Suffix(String),
    /// 前缀匹配：`value` 为域名前缀（含结尾的点）
    Prefix(String),
}

#[derive(Clone, Debug, Default)]
pub struct Whitelist {
    patterns: Vec<Pattern>,
}

impl Whitelist {
    /// 从文本解析（按空白、逗号、分号分隔）
    pub fn parse(text: &str) -> Self {
        let patterns = text
            .split(|c: char| c.is_whitespace() || c == ',' || c == ';')
            .map(str::trim)
            .filter(|token| !token.is_empty())
            .filter_map(parse_pattern)
            .collect();
        Self { patterns }
    }

    pub fn is_empty(&self) -> bool {
        self.patterns.is_empty()
    }

    pub fn len(&self) -> usize {
        self.patterns.len()
    }

    /// 可以主动解析的名字（用于不依赖 DNS 拦截的直接放行）：
    /// 后缀模式给出其基域名本身（`hub.corp.cn` → `hub.corp.cn`）；
    /// 前缀模式（`api.*`）没有确定的名字，无法主动解析。
    pub fn resolvable_names(&self) -> Vec<String> {
        let mut names: Vec<String> = self
            .patterns
            .iter()
            .filter_map(|pattern| match pattern {
                Pattern::Suffix(name) => Some(name.clone()),
                Pattern::Prefix(_) => None,
            })
            .collect();
        names.sort();
        names.dedup();
        names
    }

    /// 域名是否命中白名单
    pub fn matches(&self, domain: &str) -> bool {
        let domain = domain.trim_end_matches('.').to_ascii_lowercase();
        if domain.is_empty() {
            return false;
        }
        self.patterns.iter().any(|pattern| match pattern {
            Pattern::Suffix(suffix) => {
                domain == *suffix || domain.ends_with(&format!(".{suffix}"))
            }
            Pattern::Prefix(prefix) => domain.starts_with(prefix.as_str()),
        })
    }
}

fn parse_pattern(token: &str) -> Option<Pattern> {
    let raw = token.trim().to_ascii_lowercase();
    if raw.is_empty() {
        return None;
    }
    // 前缀匹配：`api.*`
    if let Some(prefix) = raw.strip_suffix(".*") {
        let prefix = prefix.trim_end_matches('.');
        return (!prefix.is_empty()).then(|| Pattern::Prefix(format!("{prefix}.")));
    }
    // 前缀匹配：`api.`（显式以点结尾）
    if let Some(prefix) = raw.strip_suffix('.') {
        return (!prefix.is_empty()).then(|| Pattern::Prefix(format!("{prefix}.")));
    }
    // 后缀匹配：`*.example.com` 与 `example.com` 等价（自身 + 所有子域）
    let suffix = raw.strip_prefix("*.").unwrap_or(&raw).trim_end_matches('.');
    (!suffix.is_empty()).then(|| Pattern::Suffix(suffix.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn suffix_and_prefix_matching() {
        let list = Whitelist::parse("example.com, *.corp.cn, api.*");
        assert!(list.matches("example.com"));
        assert!(list.matches("www.example.com"));
        assert!(list.matches("a.b.example.com"));
        assert!(list.matches("EXAMPLE.COM"));
        assert!(list.matches("corp.cn"));
        assert!(list.matches("mail.corp.cn"));
        assert!(list.matches("api.foo.net"));
        assert!(list.matches("API.Foo.NET"));
        assert!(!list.matches("api."));
        assert!(!list.matches("notexample.com"));
        assert!(!list.matches("example.com.evil.net"));
        assert!(!list.matches("xapi.foo.net"));
    }

    #[test]
    fn resolvable_names_skip_prefix_patterns() {
        let list = Whitelist::parse("*.corp.cn\nhub.corp.cn\napi.*\n");
        assert_eq!(
            list.resolvable_names(),
            vec!["corp.cn".to_string(), "hub.corp.cn".to_string()]
        );
    }
}
