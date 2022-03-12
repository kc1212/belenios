# Belenios

## Build and test
```
cargo test
cargo build
cargo run --example belenios_sim -- -h # for CLI options
```
Use the `--release` flag for better performance.

## Limitations
- Only binary votes are supported.
- All trustees need to be online to decrypt the ballot, i.e., m = t + 1.
As a result, there is no need to use Shamir secret sharing for trustee's initial secret,
we just use additive secret sharing.
- This is a toy implementation (not constant time, not side-channel resistant, etc.)

## Resources
- Reference: https://hal.inria.fr/hal-02066930/document
- ZKP details: https://hal.inria.fr/hal-01576379/document