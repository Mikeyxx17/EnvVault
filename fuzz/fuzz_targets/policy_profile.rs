#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Some((selector, payload)) = data.split_first() else {
        return;
    };
    if selector & 1 == 0 {
        envvault::fuzzing::parse_policy(payload);
    } else {
        envvault::fuzzing::parse_profile(payload);
    }
});
