use super::message::RouteRule;

/// Simple tag-based router.
pub struct Router {
    rules: Vec<RouteRule>,
    /// Default tag if no rule matches.
    default_tag: Option<String>,
}

impl Router {
    pub fn new() -> Self {
        Self {
            rules: Vec::new(),
            default_tag: None,
        }
    }

    pub fn with_rules(rules: Vec<RouteRule>) -> Self {
        Self {
            rules,
            default_tag: None,
        }
    }

    pub fn set_rules(&mut self, rules: Vec<RouteRule>) {
        self.rules = rules;
    }

    pub fn set_default_tag(&mut self, tag: Option<String>) {
        self.default_tag = tag;
    }

    /// Resolve target to a routing tag.
    pub fn resolve(&self, target: &str) -> Option<String> {
        // Extract host from target (strip port if present)
        let host = target.split(':').next().unwrap_or(target);

        for rule in &self.rules {
            if self.matches(&rule.pattern, host) {
                return Some(rule.tag.clone());
            }
        }

        self.default_tag.clone()
    }

    fn matches(&self, pattern: &str, host: &str) -> bool {
        // Simple matching:
        // - "*.example.com" matches subdomains
        // - "example.com" matches exact
        // - "*" matches all
        if pattern == "*" {
            return true;
        }

        if let Some(suffix) = pattern.strip_prefix("*.") {
            // Wildcard subdomain match
            host.ends_with(suffix) || host == suffix.strip_prefix('.').unwrap_or(suffix)
        } else {
            // Exact match
            host == pattern
        }
    }
}

impl Default for Router {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_router_exact_match() {
        let router = Router::with_rules(vec![RouteRule {
            pattern: "example.com".to_string(),
            tag: "direct".to_string(),
        }]);

        assert_eq!(router.resolve("example.com:443"), Some("direct".to_string()));
        assert_eq!(router.resolve("example.com"), Some("direct".to_string()));
        assert_eq!(router.resolve("other.com"), None);
    }

    #[test]
    fn test_router_wildcard_match() {
        let router = Router::with_rules(vec![RouteRule {
            pattern: "*.google.com".to_string(),
            tag: "proxy".to_string(),
        }]);

        assert_eq!(
            router.resolve("www.google.com:443"),
            Some("proxy".to_string())
        );
        assert_eq!(
            router.resolve("mail.google.com"),
            Some("proxy".to_string())
        );
        assert_eq!(router.resolve("google.org"), None);
    }

    #[test]
    fn test_router_default_tag() {
        let mut router = Router::new();
        router.set_default_tag(Some("fallback".to_string()));

        assert_eq!(
            router.resolve("anything.com"),
            Some("fallback".to_string())
        );
    }
}
