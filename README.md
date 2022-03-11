# Belenios

## Build and test
```
cargo build
cargo test
```
Use the `--release` flag for better performance.

## Limitations
- This is a toy implementation (not constant time, not side-channel resistant)
- Only binary votes are supported
- All trustees need to be online, i.e., m = t + 1

## Resources
- paper: https://hal.inria.fr/hal-02066930/document
- ZK: https://hal.inria.fr/hal-01576379/document
- DKG: https://members.loria.fr/VCortier/files/Papers/WPES2013.pdf
- Related presentation: https://www.youtube.com/watch?v=Fzj29WTVWb8