#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    envvault::fuzzing::parse_dotenv(data);
});
