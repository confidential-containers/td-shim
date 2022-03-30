#!/bin/bash

if [[ ! $PWD =~ td-shim$ ]]; then
    pushd ..
fi

pkill screen

cmds=(
    "td-loader"
    "td-uefi-pi"
)

fuzz_time=3600

afl() {
    if [ "core" != $(cat /proc/sys/kernel/core_pattern) ]; then
        if [ $(id -u) -ne 0 ]; then
            if [[ $PWD =~ td-shim$ ]]; then
                pushd sh_script
                expect switch_root_run_cmd.sh
                popd
            else
                expect switch_root_run_cmd.sh
            fi
        else
            echo core >/proc/sys/kernel/core_pattern
            pushd /sys/devices/system/cpu
            echo performance | tee cpu*/cpufreq/scaling_governor
            popd
        fi
    fi

    for path in ${cmds[@]}; do
        pushd $path
        fuzz_list=$(ls fuzz/fuzz_targets | grep afl | cut -d. -f1)
        for fuzz in $fuzz_list; do
            screen -ls | grep $fuzz
            if [[ $? -ne 0 ]]; then
                screen -dmS $fuzz
            fi
            if [[ ! -d fuzz/artifacts/$fuzz ]]; then
                mkdir -p fuzz/artifacts/$fuzz
            fi
            if [[ "$(ls -A fuzz/artifacts/$fuzz/default/crashes)" != "" ]]; then
                echo echo -e "\033[31m There are some crashes \033[0m"
                echo -e "\033[31m Path in $path/fuzz/artifacts/$fuzz/default/crashes \033[0m"
            fi
            cargo afl build --manifest-path fuzz/Cargo.toml --bin $fuzz --features fuzz --no-default-features
            seed=$(echo $fuzz | cut -d_ -f2)
            screen -x -S $fuzz -p 0 -X stuff "cargo afl fuzz -i fuzz/seeds/$seed -o fuzz/artifacts/$fuzz fuzz/target/debug/$fuzz"
            screen -x -S $fuzz -p 0 -X stuff $'\n'
            echo "fuzzing... $fuzz_time seconds ..."
            sleep $fuzz_time
            screen -S $fuzz -X quit
            sleep 5
        done
        popd
    done
}

libfuzzer() {

    for path in ${cmds[@]}; do
        pushd $path
        fuzz_list=$(cargo fuzz list)
        for fuzz in $fuzz_list; do
            if [[ $fuzz =~ "afl" ]]; then
                continue
            fi
            if [ ! -d "fuzz/corpus/$fuzz" ]; then
                mkdir -p fuzz/corpus/$fuzz
            fi
            cp fuzz/seeds/$fuzz/* fuzz/corpus/$fuzz
            screen -ls | grep $fuzz
            if [[ $? -ne 0 ]]; then
                screen -dmS $fuzz
            fi
            screen -x -S $fuzz -p 0 -X stuff "cargo fuzz run $fuzz"
            screen -x -S $fuzz -p 0 -X stuff $'\n'
            echo "fuzzing... $fuzz_time seconds ..."
            sleep $fuzz_time
            screen -S $fuzz -X quit
            sleep 5
        done
        popd
    done
}

case "${1:-}" in
afl) afl ;;
*) libfuzzer ;;
esac
