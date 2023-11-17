# td-shim-tee-info-hash

This tool can calculate MRTD(Implemented) and RTMR(WIP) values base upon inputs, e.g. shim binary, td hob, payload and payload parameter. And it can generate a tee hash info binary at last. 

A json format td manifest file is required and includes informations: attributes, xfam, mrconfigid, mrowner, mroenerconfig. Example [sample_manifest.json](sample_manifest.json)

## Tool Usage

```
USAGE:
    td-shim-tee-info-hash [OPTIONS] --image <image> --manifest <manifest> --seperator 0

OPTIONS:
    -h, --help                     Print help information
    -i, --image <image>            shim binary file
    -l, --log-level <log-level>    logging level: [off, error, warn, info, debug, trace] [default:
                                   info]
    -m, --manifest <manifest>      td manifest
    -o, --out_bin <output>          output tee info hash binary
    -V, --version                  Print version information
    -s, --seperator <u32>          The seperator to be extended into rtmr
```

example:<br>
```
cargo run -p td-shim-tools --bin td-shim-tee-info-hash --features tee -- --manifest <td_manifest> --image <td_shim_binary> --out_bin <tee_info_hash_bin> --seperator 0
```
