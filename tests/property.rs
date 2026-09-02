//! Property checks for hierarchical scope and canonical evidence identity.

use canonical_company_auditor::evidence::digest;
use canonical_company_auditor::model::scope_contains;
use proptest::prelude::*;
use serde_json::json;

proptest! {
    #[test]
    fn scope_containment_respects_segment_boundaries(segment in "[a-z][a-z0-9_-]{0,20}") {
        let root = "organization/example";
        let child = format!("{root}/{segment}");
        let lookalike = format!("{root}-{segment}");
        prop_assert!(scope_contains(root, &child));
        prop_assert!(!scope_contains(root, &lookalike));
    }

    #[test]
    fn changing_a_scalar_changes_its_digest(value in any::<i64>(), other in any::<i64>()) {
        prop_assume!(value != other);
        let first = digest(&json!({"value": value}));
        let second = digest(&json!({"value": other}));
        prop_assert!(first.is_ok());
        prop_assert!(second.is_ok());
        if let (Ok(first), Ok(second)) = (first, second) {
            prop_assert_ne!(first, second);
        }
    }
}
