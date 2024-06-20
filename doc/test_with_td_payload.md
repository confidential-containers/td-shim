# Test with TD Payload
TD-Shim has some test cases rely on TDX specific environment. Therefore, this simple test framework is created to support the test.

## Test framework code structure
All codes of test framework are located in [tests/test-td-payload](../tests/test-td-payload).

```
-- tests
---- test-td-payload
------ main.rs
------ lib.rs
------ test.json
------ testtdinfo.rs
------ ...
```

[main.rs](../tests/test-td-payload/src/main.rs): It defines strut `TestCases`. Main flow: Init `td_logger`-> Init heap-> Init `TestSuite` -> Build test cases(Parse test configuration data in CFV) -> Add test cases in `TestSuite` -> Run test cases -> Log test result. 

[lib.rs](../tests/test-td-payload/src/lib.rs)：It defines enum `TestResult`、trait `TestCase` 、struct `TestSuite` and `TestSuite.run`. `TestSuite.run` will log result of each test case and count summary test result. 

[test.json](../tests/test-td-payload/src/test.json): This is a json format test configuration data file. The structure should be correspond with struct `TestCases` in main.rs. It will be enrolled in CFV with tool [td-shim-enroll](../td-shim-tools/src/bin/td-shim-enroll/main.rs).

[testtdinfo.rs](../tests/test-td-payload/src/testtdinfo.rs): This is a test case sample. Implement test struture and the `TestCase` trait(`setup` `run` `teardown` `get_name` `get_result`) for test structure.  

## Build Test Image with Test TD Payload
Refer to [README](../README.md), using PE as example:
### Build test TD payload
```
$ cd tests
$ cargo xbuild -p test-td-payload --target x86_64-unknown-none --release --features=main,tdx
$ cd ..
```

### Generate final.bin
```
$ cargo xbuild -p td-shim --target x86_64-unknown-none --release --features=main,tdx --no-default-features
$ cargo run -p td-shim-tools --bin td-shim-ld -- target/x86_64-unknown-none/release/ResetVector.bin target/x86_64-unknown-none/release/td-shim -t executable -p target/x86_64-unknown-uefi/release/test-td-payload.efi -o target/release/final-pe.bin
```

### Enroll json file in CFV
```
$ cargo run -p td-shim-tools --features="enroller" --bin td-shim-enroll target/release/final-pe.bin -f F10E684E-3ABD-20E4-5932-8F973C355E57 tests/test-td-payload/src/test.json -o target/release/final.test.bin
```

The output file **final.test.bin** with [test.json](../tests/test-td-payload/src/test.json) is located in the same folder with input final.bin. 

## Json Test Configuration Data Example
```
{	    
    "tcs001": {
        "name": "tdinfo001",
        "expected": {
            "gpaw": 52,
            "attributes": 0,
            "max_vcpus": 1,
            "num_vcpus": 1,
            "vcpu_index":0,
            "rsvd": [0,0,0,0,0]
        },
        "result": "None",
        "run": true  
    }
}
```

## Test Result Show
```
INFO - ---------------------------------------------
INFO - Start to run tests.
INFO - ---------------------------------------------
INFO - [Test: tdinfo001]
INFO - td_info data addr: 0x3f7ff9e8
INFO - gpaw - 52
INFO - max_vcpus - 1
INFO - num_vcpus - 1
INFO - rsvd - [0, 0, 0]
INFO - [Test: tdinfo001] - Pass
INFO - ---------------------------------------------
INFO - [Test: tdinfo002]
INFO - td_info data addr: 0x3f7ff9e8
INFO - gpaw - 52
INFO - Check max_vcpus fail - Expected 8: Actual 1
INFO - [Test: tdinfo002] - Fail
INFO - ---------------------------------------------
INFO - [Test: tdinfo003]
INFO - td_info data addr: 0x3f7ff9e8
INFO - Check gpaw fail - Expected 48: Actual 52
INFO - [Test: tdinfo003] - Fail
INFO - ---------------------------------------------
INFO - Test Result: Total run 3 tests; 1 passed; 2 failed
```