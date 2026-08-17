//! Process target for the crash / power-loss harness.
//!
//! Built only with `--features fault-injection`. It creates and recovers a
//! throwaway Vault and must never be pointed at a Vault that holds real
//! secrets.

#![forbid(unsafe_code)]

fn main() {
    std::process::exit(envvault::fault_injection::main_from_args(
        std::env::args_os(),
    ));
}
