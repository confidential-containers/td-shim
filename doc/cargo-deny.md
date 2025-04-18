## cargo-deny

cargo-deny is a cargo plugin that lets you lint your project's 
dependency graph to ensure all your dependencies conform to 
your expectations and requirements.

**Checks**

cargo-deny supports several different classes of checks that 
can be performed on your project's crate graph. By default, 
cargo deny check will execute all of the supported checks, 
falling back to the default configuration for that check 
if one is not explicitly specified.

- licenses

    Checks the license information for each crate.

- bans

    Checks for specific crates in your graph, as well as duplicates.

- advisories

    Checks advisory databases for crates with security vulnerabilities, 
or that have been marked as Unmaintained, or which have been yanked from 
their source registry.

- sources

    Checks the source location for each crate.

Install:

`cargo install --locked cargo-deny`

if the project edition is not 2021, you can install 0.10.3.

`cargo install cargo-deny --version 0.10.3`

Checks:

`cargo deny check`

Check a few of them

`cargo deny check bans sources`

If you want to use a configuration file and ignore some options.

```
# Create deny.toml file
cargo init
```

GitHub Action

For GitHub projects, one can run cargo-deny automatically as 
part of continuous integration using a GitHub Action:

```

name: cargo-deny
on: [push, pull_request]
jobs:
  cargo-deny:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        checks:
          - advisories
          - sources
          - bans
          - licenses

    # Prevent sudden announcement of a new advisory from failing ci:
    continue-on-error: ${{ matrix.checks == 'sources' }}

    steps:
    - uses: actions/checkout@v2
      with:
        submodules: recursive
        
    - run: make preparation
    - uses: EmbarkStudios/cargo-deny-action@v1
      with:
        command: check ${{ matrix.checks }}
```

Reference:

[cargo-deny book](https://embarkstudios.github.io/cargo-deny/index.html)

[cargo-deny github](https://github.com/EmbarkStudios/cargo-deny)