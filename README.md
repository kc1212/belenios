# Belenios

This is a toy implementation of the Belenios electronic voting system.
See the [paper](https://hal.inria.fr/hal-02066930/document) for how it works.

## Build and test
```
cargo test
cargo run --example belenios_sim
cargo run --example belenios_sim -- -h # for CLI options
```
Use the `--release` flag for better performance.

## Limitations
- Only binary votes are supported.
- All trustees need to be online to decrypt the ballot.
As a result, there is no need to use Shamir secret sharing for trustee's initial secret,
we just use additive secret sharing.
- Only the basic protocol from the [paper](https://hal.inria.fr/hal-02066930/document) is implemented, 
not the one from the [specification](https://www.belenios.org/specification.pdf).
- This is a toy implementation (not constant time, not side-channel resistant or thoroughly tested, etc.)

## Resources
- https://hal.inria.fr/hal-02066930/document
- https://hal.inria.fr/hal-01576379/document
