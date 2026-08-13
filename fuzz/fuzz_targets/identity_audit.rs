#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Some((selector, payload)) = data.split_first() else {
        return;
    };
    match selector & 7 {
        0 => envvault::fuzzing::parse_identity_registry(payload),
        1 => envvault::fuzzing::parse_audit_event(payload),
        2 => envvault::fuzzing::parse_audit_segment_v2(payload),
        3 => envvault::fuzzing::parse_audit_anchor_v2(payload),
        4 => envvault::fuzzing::parse_audit_recovery(payload),
        5 => envvault::fuzzing::parse_audit_descriptor_v2(payload),
        _ => envvault::fuzzing::parse_audit_recovery(payload),
    }
});
