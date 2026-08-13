//! Property tests for stable identifiers, exact authorization, and value-free Profiles.

use envvault::{
    identity::{Caller, CallerId, CallerKind},
    policy::{
        AuthorizationRequest, DenyReason, Operation, PolicyDecision, PolicyEffect, PolicyEvaluator,
        PolicyRule, PolicySet,
    },
    profile::{Profile, ProfileBinding},
    secret::SecretId,
};
use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn opaque_identifiers_round_trip_canonically(
        caller_bytes in any::<[u8; CallerId::BYTE_LENGTH]>(),
        secret_bytes in any::<[u8; SecretId::BYTE_LENGTH]>(),
    ) {
        let caller_id = CallerId::from_bytes(caller_bytes);
        let secret_id = SecretId::from_bytes(secret_bytes);

        prop_assert_eq!(caller_id.to_string().parse::<CallerId>(), Ok(caller_id));
        prop_assert_eq!(secret_id.to_string().parse::<SecretId>(), Ok(secret_id));
    }

    #[test]
    fn one_allow_rule_never_grants_another_exact_tuple(
        caller_bytes in any::<[u8; CallerId::BYTE_LENGTH]>(),
        other_caller_bytes in any::<[u8; CallerId::BYTE_LENGTH]>(),
        secret_bytes in any::<[u8; SecretId::BYTE_LENGTH]>(),
        other_secret_bytes in any::<[u8; SecretId::BYTE_LENGTH]>(),
    ) {
        let caller = Caller::new(CallerId::from_bytes(caller_bytes), CallerKind::Application);
        let secret = SecretId::from_bytes(secret_bytes);
        let permitted = AuthorizationRequest::new(caller, secret, Operation::Use);
        let mut policy = PolicySet::new();
        prop_assert!(policy.insert(PolicyRule::new(
            caller,
            secret,
            Operation::Use,
            PolicyEffect::Allow,
        )));
        prop_assert_eq!(policy.evaluate(&permitted), PolicyDecision::Allow);

        let other_caller = Caller::new(
            CallerId::from_bytes(other_caller_bytes),
            CallerKind::Application,
        );
        let other_secret = SecretId::from_bytes(other_secret_bytes);
        if other_caller != caller || other_secret != secret {
            let decision = policy.evaluate(&AuthorizationRequest::new(
                other_caller,
                other_secret,
                Operation::Use,
            ));
            prop_assert_eq!(decision, PolicyDecision::Deny(DenyReason::NoMatchingGrant));
        }
        prop_assert_eq!(
            policy.evaluate(&AuthorizationRequest::new(caller, secret, Operation::ReadPlaintext)),
            PolicyDecision::Deny(DenyReason::NoMatchingGrant),
        );
    }

    #[test]
    fn profile_encoding_is_deterministic_and_value_free(
        first in any::<[u8; SecretId::BYTE_LENGTH]>(),
        second in any::<[u8; SecretId::BYTE_LENGTH]>(),
    ) {
        prop_assume!(first != second);
        let first_id = SecretId::from_bytes(first);
        let second_id = SecretId::from_bytes(second);
        let profile = Profile::new(vec![
            ProfileBinding::new("Z_TOKEN", second_id)?,
            ProfileBinding::new("A_TOKEN", first_id)?,
        ])?;
        let encoded = profile.encode()?;
        let decoded = Profile::decode(&encoded)?;

        prop_assert_eq!(&decoded, &profile);
        prop_assert!(!encoded.windows(5).any(|window| window.eq_ignore_ascii_case(b"value")));
        prop_assert_eq!(decoded.encode()?, encoded);
    }
}
