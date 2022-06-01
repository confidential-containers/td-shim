# td-reproducible-tool

## Background

Elements break reproducible build (x86_64-unknown-uefi + target x86_64-unknown-none) <br>
 <br>
```
1. Debug related sections (PE + ELF) 
2. Code base path like \home\USERNAME\rust-td-payload\xxx\xxx.rs (PE + ELF) 
3. CARGO_HOME like \home\USERNAME\.cargo\xxx\xxx.rs (PE + ELF) 
4. RUSTUP_HOME like \home\USERNAME\.rustup\xxx\xxx.rs (PE + ELF) 
5. TimeDateStamp field in COFF file header (PE only) 
```

Solution: <br>

```
1. Use strip = "symbols" option to [profile.release] 
2. Use strip = "symbols" option to [profile.release] 
3. Use a post-build tool to zero CARGO_HOME string 
4. Use a post-build tool to zero RUSTUP_HOME string
5. Use a post-build tool to zero TimeDateStamp for PE
```
NOTE: 3 and 4 may be resolved directly after rust-lang RFC 3127. This tool provide a temp solution to solve 3 and 4 before RFC is implemented.

NOTE: 1 and 2 are not applied because this strip feature has potential stability issue. For example, [bug](https://github.com/confidential-containers/td-shim/issues/272). It can be enabled after the strip becomes more robust.

## tool usage

```
td-reproducible-tool [OPTIONS]

TD REPRODUCIBLE TOOL

Optional arguments:
  -h,--help             Show this help message and exit
  -w,--workspace WORKSPACE
                        Where to find the target folder.
  -n,--name NAME        Name for the compiled binary.
  -t,--target TARGET    The built target to find.
  -p,--profile PROFILE  The built profile to find.
  -c,--cargo_home CARGO_HOME
                        The cargo home. If not specify, system variable CARGO_HOME will be searched.
  -r,--rustup_home RUSTUP_HOME
                        The rustup home. If not specify, system variable RUSTUP_HOME will be searched.
  -v,--verbose          Verbose output.
  -s,--strip_path       Strip rust file path.
```

example:<br>
Command used under x86_64-unknown-uefi target:
```
cargo run -p td-reproducible-tool -- -n rust-td-payload --target x86_64-unknown-uefi -p release -v
```
is equal to 
```
cargo run -p td-reproducible-tool -- -w "." -n rust-td-payload.efi -t x86_64-unknown-uefi -p release -v
```
<br>
Command used under x86_64-unknown-none target:

```
cargo run -p td-reproducible-tool -- -n rust-td-payload --target x86_64-unknown-none -p release -v
```