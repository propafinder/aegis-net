//! Decision after the protected store has reported online status. This module
//! never opens identity files, recovers a response, sends a request or grants
//! capture. The caller must use protected store custody and recheck issuance.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RenewalPlan {
    UseExisting,
    Renew,
}

pub fn after_protected_status(
    renewal_allowed: bool,
    pending: bool,
    renewal_due: bool,
) -> Result<RenewalPlan, &'static str> {
    if pending || renewal_due {
        if !renewal_allowed {
            return Err("online renewal is disabled; ingress remains stopped");
        }
        Ok(RenewalPlan::Renew)
    } else {
        Ok(RenewalPlan::UseExisting)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn existing_only_never_allows_pending_or_due_state() {
        assert_eq!(
            after_protected_status(false, false, false),
            Ok(RenewalPlan::UseExisting)
        );
        for (pending, due) in [(true, false), (false, true), (true, true)] {
            assert!(after_protected_status(false, pending, due).is_err());
        }
    }

    #[test]
    fn automatic_policy_reuses_or_renews_only_from_protected_status() {
        assert_eq!(
            after_protected_status(true, false, false),
            Ok(RenewalPlan::UseExisting)
        );
        for (pending, due) in [(true, false), (false, true), (true, true)] {
            assert_eq!(
                after_protected_status(true, pending, due),
                Ok(RenewalPlan::Renew)
            );
        }
    }
}
