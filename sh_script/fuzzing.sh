#!/bin/bash

if [[ ! $PWD =~ td-shim$ ]]; then
    pushd ..
fi

pkill screen

cmds=(
    "td-loader"
    "td-uefi-pi"
)

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

    for i in ${cmds[@]}; do
        pushd $i/fuzz
        fuzz_list=$(ls fuzz_targets | grep afl | cut -d. -f1)
        for j in $fuzz_list; do
            screen -ls | grep $j
            if [[ $? -ne 0 ]]; then
                screen -dmS $j
            fi
            if [[ ! -d artifacts/$j ]]; then
                mkdir -p artifacts/$j
            fi
            if [[ "$(ls -A artifacts/$j/default/crashes)" != "" ]]; then
                echo echo -e "\033[31m There are some crashes \033[0m"
                echo -e "\033[31m Path in $i/fuzz/artifacts/$j/default/crashes \033[0m"
            fi
            cargo afl build --bin $j --features fuzz --no-default-features
            seed=$(echo $j | cut -d_ -f2)
            screen -x -S $j -p 0 -X stuff "cargo afl fuzz -i ../../data/fuzz_seeds/$seed -o artifacts/$j target/debug/$j"
            screen -x -S $j -p 0 -X stuff $'\n'
            sleep 3600
            screen -S $j -X quit
            sleep 5
        done
        popd
    done
}

libfuzzer() {

    for i in ${cmds[@]}; do
        pushd $i
        fuzz_list=$(cargo fuzz list)
        for j in $fuzz_list; do
            if [[ $j =~ "afl" ]]; then
                continue
            fi
            if [ ! -d "fuzz/corpus/$j" ]; then
                mkdir -p fuzz/corpus/$j
            fi
            cp ../data/fuzz_seeds/$j/* fuzz/corpus/$j
            screen -ls | grep $j
            if [[ $? -ne 0 ]]; then
                screen -dmS $j
            fi
            screen -x -S $j -p 0 -X stuff "cargo fuzz run $j"
            screen -x -S $j -p 0 -X stuff $'\n'
            sleep 3600
            screen -S $j -X quit
            sleep 5
        done
        popd
    done
}

case "${1:-}" in
afl) afl ;;
*) libfuzzer ;;
esac
