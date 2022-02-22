# rust static analyzer

## rudra

[rudra](https://github.com/sslab-gatech/Rudra) is a tool for Rust Memory Safety & Undefined Behavior Detection.

[Currently rust can't work in the workspace(2021-08-31)](https://github.com/sslab-gatech/Rudra/issues/11)

The use of docker will have a depend problem.

https://github.com/sslab-gatech/Rudra/blob/master/DEV.md

### clone rudra project and install rudra

use nightly-2021-08-20

```
git clone https://github.com/bjorn3/Rudra.git
cd rudra

# Toolchain setup
rustup install nightly-2021-08-20
rustup override set nightly-2021-08-20
rustup component add rustc-dev
rustup component add miri

# Environment variable setup, put these in your `.bashrc`
export RUDRA_RUST_CHANNEL=nightly-2021-08-20
export RUDRA_RUNNER_HOME="<your runner home path - use setup_rudra_runner_home.py>"

export RUSTFLAGS="-L $HOME/.rustup/toolchains/${RUDRA_RUST_CHANNEL}-x86_64-unknown-linux-gnu/lib"
export LD_LIBRARY_PATH="${LD_LIBRARY_PATH}:$HOME/.rustup/toolchains/${RUDRA_RUST_CHANNEL}-x86_64-unknown-linux-gnu/lib"

# Test your installation
python test.py
```
### How to use Rudra
```
# this executes: cargo install --path "$(dirname "$0")" --force
./install-release

rudra --crate-type lib tests/unsafe_destructor/normal1.rs  # for single file testing (you need to set library include path, or use `cargo run` instead)
cargo rudra  # for crate compilation
Rudra Configurations
```

Now rudra works on nightly-2021-08-20, the items that need to be checked,

need to change the toolchain data to nightly-2021-08-20.

Otherwise rudra won't work.

If there are deprecated warnings, please use`cargo rudra` ignore the warning.

If there is component A and security bug component B.
```
mkdir workspace
cd workspace
echo "[workspace]" > Cargo.toml
echo 'members = ["member","member1"]' >> Cargo.toml
cargo new member

cargo new --lib member1
echo "struct Atom<P>(P);" > member1/src/lib.rs
echo "unsafe impl<P: Ord> Send for Atom<P> {}" >> member1/src/lib.rs

echo 'member1 = {path="../member1"}' >> member/Cargo.toml
# pass
cargo build -p member
# pass
cargo build -p member1
cd member
cargo rudra

2021-09-09 23:19:12.603401 |INFO | [rudra-progress] Rudra finished
Error (SendSyncVariance:/PhantomSendForSend/NaiveSendForSend/RelaxSend): Suspicious impl of `Send` found
-> member1/src/lib.rs:2:1: 2:40
unsafe impl<P: Ord> Send for Atom<P> {}
2021-09-09 23:19:12.760596 |INFO | [rudra-progress] Rudra started
```
Scan Component A can find the issue.
