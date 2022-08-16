# rust static analyzer

## rudra

rudra description:
 > Rudra is tied to a specific Rust compiler version, and it can only analyze projects that compiles with this version of the compiler. master branch uses nightly-2021-08-20 version of Rust right now. 

**The current rust version is nightly-2022-05-15, so now rudra can not run.**


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

## Prusti
Prusti description:
> [Prusti](https://www.pm.inf.ethz.ch/research/prusti.html) is a prototype verifier for Rust, built upon the [Viper verification infrastructure](https://www.pm.inf.ethz.ch/research/viper.html).

### Command-line setup
Alternatively, Prusti can be set up by downloading the [precompiled binaries](https://github.com/viperproject/prusti-dev/releases) available from the project page. Currently it provides binaries for Windows, macOS, and Ubuntu. Releases marked as "Pre-release" may contain unstable or experimental features.

#### Setup on Ubuntu:
Install dependencies:
```
sudo apt-get update
sudo apt-get install openjdk-11-jdk libssl-dev
```

Download prusti binaries:
```
mkdir prusti && cd prusti
wget https://github.com/viperproject/prusti-dev/releases/download/v-2022-08-10-0013/prusti-release-ubuntu.zip # You can prefer newer version precompiled binaries
unzip prusti-release-ubuntu.zip
chmod +x cargo-prusti prusti-* viper_tools/z3/bin/z3
```
Add prusti path in system environment.

#### Run Prusti Scan
Firstly set variables to set "unsupported features" and "internal errors" to warnings
```
export PRUSTI_SKIP_UNSUPPORTED_FEATURES=true
export PRUSTI_INTERNAL_ERRORS_AS_WARNINGS=true
```
Run command to scan each crate:
```
cd td-uefi-pi && cargo-prusti
```

## MIRAI

### Why: 
Current static tool like clippy can't detect rust programs that terminate abruptly and disgracefully.

### How:
https://github.com/facebookexperimental/MIRAI

MIRAI does this by doing a reachability analysis: Given an entry point, it will analyze all possible code paths that start from that entry point and determine if any of them can reach a program point where an abrupt runtime termination will happen. 

### How to use

#### Step 1: Install MIRAI

```
git clone https://github.com/facebookexperimental/MIRAI.git
cd MIRAI
git checkout c6c1a4f84c2b463c393761a8c60f6d084a11389b
cargo install --locked --path ./checker
```

Note: MIRAI required rust toolchain version: nightly-2022-08-08

#### Step 2: Scan your crate

Use td-shim as example

```
git clone https://github.com/confidential-containers/td-shim.git; cd td-shim
git checkout a0b51c0f7f4736c65de8a6eb9644e31e762df623
echo "nightly-2022-08-08" > rust-toolchain
# Run command to scan td-shim crate
pushd td-shim
cargo mirai --features="main,tdx"
popd
```

Run command to scan other crate like this:
```
pushd td-uefi-pi
cargo mirai
popd
```

### Limitation

* MIRAI requires a specific rust toolchain.
* MIRAI needs to consume a lot of memory.(td-shim 32G+)
