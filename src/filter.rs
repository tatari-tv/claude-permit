/// Filter items by patterns using cascading match: exact -> prefix -> substring.
///
/// - Empty patterns returns all items unchanged.
/// - Otherwise tries each level in order; returns the first non-empty result set.
pub fn filter_by_patterns<T, F>(items: Vec<T>, patterns: &[String], key: F) -> Vec<T>
where
    F: Fn(&T) -> &str,
{
    if patterns.is_empty() {
        return items;
    }

    let matched_indices = |f: &dyn Fn(&str, &str) -> bool| -> Vec<usize> {
        items
            .iter()
            .enumerate()
            .filter(|(_, item)| patterns.iter().any(|p| f(key(item), p)))
            .map(|(i, _)| i)
            .collect()
    };

    type Matcher = Box<dyn Fn(&str, &str) -> bool>;
    let levels: [Matcher; 3] = [
        Box::new(|k: &str, p: &str| k == p),
        Box::new(|k: &str, p: &str| k.starts_with(p)),
        Box::new(|k: &str, p: &str| k.contains(p)),
    ];

    for level in &levels {
        let indices = matched_indices(level.as_ref());
        if !indices.is_empty() {
            return items
                .into_iter()
                .enumerate()
                .filter(|(i, _)| indices.contains(i))
                .map(|(_, item)| item)
                .collect();
        }
    }

    vec![]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn empty_patterns_returns_all() {
        let items = vec!["foo", "bar", "baz"];
        assert_eq!(filter_by_patterns(items, &[], |s| s), vec!["foo", "bar", "baz"]);
    }

    #[test]
    fn exact_match_wins() {
        let items = vec!["Bash(git status:*)", "Bash(git push:*)", "Bash(git:*)"];
        let result = filter_by_patterns(items, &p(&["Bash(git status:*)"]), |s| s);
        assert_eq!(result, vec!["Bash(git status:*)"]);
    }

    #[test]
    fn prefix_match_when_no_exact() {
        let items = vec!["Bash(git status:*)", "Bash(git push:*)", "WebSearch", "Edit(**)"];
        let result = filter_by_patterns(items, &p(&["Bash"]), |s| s);
        assert_eq!(result, vec!["Bash(git status:*)", "Bash(git push:*)"]);
    }

    #[test]
    fn substring_match_when_no_prefix() {
        let items = vec!["Bash(git status:*)", "Bash(git push:*)", "WebSearch"];
        let result = filter_by_patterns(items, &p(&["git"]), |s| s);
        assert_eq!(result, vec!["Bash(git status:*)", "Bash(git push:*)"]);
    }

    #[test]
    fn multiple_patterns_same_level() {
        let items = vec!["Bash(git status:*)", "Bash(cargo build:*)", "WebSearch"];
        let result = filter_by_patterns(items, &p(&["Bash(git status:*)", "Bash(cargo build:*)"]), |s| s);
        assert_eq!(result, vec!["Bash(git status:*)", "Bash(cargo build:*)"]);
    }

    #[test]
    fn no_match_returns_empty() {
        let items = vec!["foo", "bar"];
        let result = filter_by_patterns(items, &p(&["zzz"]), |s| s);
        assert!(result.is_empty());
    }
}
