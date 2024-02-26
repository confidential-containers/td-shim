#!/bin/bash
#
# Copyright (c) 2022 Intel Corporation
#
# SPDX-License-Identifier: Apache-2.0
#
readonly script_name=${0##*/}

fuzz_folder=(
    "td-loader"
    "td-shim-interface/src"
    "td-shim"
)

function show_prompt_info() {
        cat << EOM
Usage: $(basename "$0") [OPTION]...
  -n Test case name, e.g. afl_pe, afl_all, libfuzzer_all
  -t Excution time, default is 3600
  -b Build all test case for check
  -c Enable code coverage
  Example:
  Run single test case:    bash ${script_name} -n afl_pe -t 3600
  Run all test case:       bash ${script_name} -n afl_all -t 3600
EOM
    exit 0
}

while getopts ':n:t:bch' OPT; do
    case $OPT in
        b) check_build="YES";;
        c) collect_coverage="YES";;
        h) show_prompt_info;;
        n) test_case="$OPTARG";;
        t) test_time="$OPTARG";;
        ?) show_prompt_info;;
    esac
done

if [ "$check_build" == "YES" ]; then
	echo "Build all fuzzing test case"
else
	if [[ "$test_time" != "" && "$test_time" -le "0" ]];then
		echo "Test time should be a integer number greater than 0"
        exit 1
	elif [[ "$test_time" == "" ]];then
		test_time=3600
	else
		 echo "Time: $test_time"
	fi

	if [ "$test_case" == "" ];then
		echo "Test case name should not be empty"
        exit 1
	fi
	echo "Test case: $test_case"
fi

test_check() {
    if [[ "core" != $(cat /proc/sys/kernel/core_pattern) ]]; then
        if [ $(id -u) -ne 0 ]; then
            sudo su - root <<EOF;
            echo core >/proc/sys/kernel/core_pattern;
            pushd /sys/devices/system/cpu;
            echo performance | tee cpu*/cpufreq/scaling_governor;
            popd;
            echo "root path is $PWD";
            exit;
EOF
        else
            echo core >/proc/sys/kernel/core_pattern
            pushd /sys/devices/system/cpu
            echo performance | tee cpu*/cpufreq/scaling_governor
            popd
        fi
    fi
}

search_test_case() {
	search_fuzz="NO"
	for path in ${fuzz_folder[@]};do
		pushd $path
		fuzz_list=$(cargo fuzz list)
		for fuzz in $fuzz_list;do
			if [ "$fuzz" != "$test_case" ];then
				continue
			else
				search_fuzz="YES"
				break
			fi
		done
		popd
		if [ "$search_fuzz" == "YES" ];then
			break
		fi
	done
	if [ "$search_fuzz" == "NO" ];then
		echo "Cannot find test case $test_case"
		exit 1
	fi
}

check_build() {
    for path in ${fuzz_folder[@]};do
        pushd $path
        fuzz_list=$(cargo fuzz list)
        for fuzz in ${fuzz_list[@]};do
            test_case=$fuzz
            echo "## Build test case $test_case in $path"
            echo $test_case | grep "^afl"
            if [ "$?" == "0" ];then
                cargo_build=`cargo afl build --manifest-path fuzz/Cargo.toml --bin $test_case --features fuzz --no-default-features`
                if [ "$?" != "0" ];then
                    echo "Error: Build execution failed"
                    exit 1
                fi
            fi
        done
        popd
    done 
}

run_single_case() {
    for path in ${fuzz_folder[@]};do
        temp_sw='NO'
        pushd $path
        fuzz_list=$(cargo fuzz list)
        for fuzz in ${fuzz_list[@]};do
            if [ "$fuzz" == "$test_case" ];then
                temp_sw="YES"
                break
            fi
        done
        if [ "$temp_sw" == "YES" ];then
            break
        else
            popd
        fi
    done

    echo $test_case | grep "^afl"
    if [ "$?" == "0" ];then
        echo "The test method is afl"
        if [ "${collect_coverage}" == "YES" ]; then
            export RUSTFLAGS="-C instrument-coverage"
            export LLVM_PROFILE_FILE="fuzz-%p-%m.profraw"
            find . -name "*.profraw" | xargs rm -rf
        fi

        cargo_build=`cargo afl build --manifest-path fuzz/Cargo.toml --bin $test_case --features fuzz --no-default-features`
	    if [ "$?" != "0" ];then
		    echo "Error: Build execution failed"
		    exit 1
	    else
            if [ ! -d "fuzz/artifacts/$test_case" ];then
		        mkdir -p fuzz/artifacts/$test_case
            else
                rm -rf fuzz/artifacts/$test_case
                mkdir -p fuzz/artifacts/$test_case
            fi
            kill_pro=`ps aux | grep "fuzz/target/debug/$test_case" | sed -n '3p' | awk -F ' ' '{print$2}'`
            if [ "$kill_pro" != "" ];then
                kill $kill_pro
            fi
		    timeout $test_time cargo afl fuzz -i fuzz/seeds/${test_case#*_}/ -o fuzz/artifacts/$test_case fuzz/target/debug/$test_case

            queue_seed_num=`ls -A fuzz/artifacts/$test_case/default/queue | wc -l`
            if [[ $queue_seed_num -le 1 || \
                    "`ls -A fuzz/artifacts/$test_case/default/crashes`" != "" || \
                    "`ls -A fuzz/artifacts/$test_case/default/hangs`" != "" ]]; then
                echo "Test Case: $test_case fail"
                exit 1
            else
                echo "Test Case: $test_case pass"
            fi
            
            if [ "${collect_coverage}" == "YES" ]; then
                [ -d "${test_case}_cov" ] && rm -rf "${test_case}_cov"

                grcov . -s src --binary-path fuzz/target/debug/$test_case -t html --branch --ignore-not-existing -o "${test_case}_cov"
            fi
	    fi
        popd
    else
        echo "The test method is libfuzzer"
        if [ ! -d "fuzz/corpus/$test_case" ]; then
                mkdir -p fuzz/corpus/$test_case
        else
            rm -rf fuzz/corpus/$test_case
            mkdir -p fuzz/corpus/$test_case
        fi
        cp fuzz/seeds/$test_case/* fuzz/corpus/$test_case
        kill_pro=`ps aux | grep "fuzz/corpus/$test_case" | sed -n '1p' | awk -F ' ' '{print$2}'`
        kill $kill_pro
        cargo fuzz build $test_case
        timeout $test_time cargo fuzz run $test_case

        if [[ `ls -A fuzz/corpus/$test_case | wc -l` -le 1 || \
                "`find fuzz/corpus/$test_case -name '*leak*'`" != "" || \
                "`find fuzz/corpus/$test_case -name '*timeout*'`" != "" || \
                "`find fuzz/corpus/$test_case -name '*crash*'`" != ""  ]]; then
            echo "Test Case: $test_case fail"
            exit 1
        else
            echo "Test Case: $test_case pass"
        fi

        if [ "${collect_coverage}" == "YES" ]; then
            [ -d "${test_case}_fuzz_cov" ] && rm -rf ${test_case}_fuzz_cov;

            find . -name "*.profraw" | xargs rm -rf
            cargo fuzz coverage $test_case
            grcov . -s src -b fuzz/target/x86_64-unknown-linux-gnu/release/$test_case -t html --branch --ignore-not-existing -o "${test_case}_fuzz_cov"
        fi
        popd
    fi
}

run_all_case(){
    if [ "$test_case" == "libfuzzer_all" ];then
        for path in ${fuzz_folder[@]}; do
            pushd $path
            fuzz_list=$(cargo fuzz list)
            for fuzz in $fuzz_list; do
                if [[ $fuzz =~ "afl" ]]; then
                    continue
                fi
                if [ ! -d "fuzz/corpus/$fuzz" ]; then
                    mkdir -p fuzz/corpus/$fuzz
                else
                    rm -rf fuzz/corpus/$fuzz
                    mkdir -p fuzz/corpus/$fuzz
                fi
                cp fuzz/seeds/$fuzz/* fuzz/corpus/$fuzz
                kill_pro=`ps aux | grep "fuzz/corpus/$fuzz" | sed -n '1p' | awk -F ' ' '{print$2}'`
                kill $kill_pro
                cargo fuzz build $fuzz
                timeout $test_time cargo fuzz run $fuzz
                
                if [ "${collect_coverage}" == "YES" ]; then
                    if [ ! -d "${fuzz}_fuzz_cov" ]; then
                        rm -rf ${fuzz}_fuzz_cov
                    fi
                    find . -name "*.profraw" | xargs rm -rf
                    cargo fuzz coverage $fuzz
                    grcov . -s src -b fuzz/target/x86_64-unknown-linux-gnu/release/$fuzz -t html --branch --ignore-not-existing -o "${fuzz}_fuzz_cov"
                fi
            done
            popd
        done
    else
        for path in ${fuzz_folder[@]};do
            pushd $path
            fuzz_list=$(cargo fuzz list)
            for fuzz in $fuzz_list;do
                if [[ "$fuzz" =~ "afl" ]];then
                    if [ "${collect_coverage}" == "YES" ]; then
                        export RUSTFLAGS="-C instrument-coverage"
                        export LLVM_PROFILE_FILE="fuzz-%p-%m.profraw"
                        find . -name "*.profraw" | xargs rm -rf
                    fi

                    cargo_build=`cargo afl build --manifest-path fuzz/Cargo.toml --bin $fuzz --features fuzz --no-default-features`
                    if [ "$?" != "0" ];then
                        echo "Error: Build execution failed"
                        exit 1
                    else
                        if [ ! -d "fuzz/artifacts/$fuzz" ];then
                            mkdir -p fuzz/artifacts/$fuzz
                        else
                            rm -rf fuzz/artifacts/$fuzz
                            mkdir -p fuzz/artifacts/$fuzz
                        fi
                        kill_pro=`ps aux | grep "fuzz/target/debug/$fuzz" | sed -n '3p' | awk -F ' ' '{print$2}'`
                        if [ "$kill_pro" != "" ];then
                            kill $kill_pro
                        fi
                        timeout $test_time cargo afl fuzz -i fuzz/seeds/${fuzz#*_}/ -o fuzz/artifacts/$fuzz fuzz/target/debug/$fuzz

                        if [ "${collect_coverage}" == "YES" ]; then
                            if [ -d "${fuzz}_cov" ]; then
                                rm -rf "${fuzz}_cov"
                            fi
                            grcov . -s src --binary-path fuzz/target/debug/$fuzz -t html --branch --ignore-not-existing -o "${fuzz}_cov"
                        fi
                    fi
                else
                    continue
                fi
            done
            popd
        done
    fi
}

check_test_result() {
    check_total_result=0
	if [ "$test_case" == "libfuzzer_all" ];then
        for path in ${fuzz_folder[@]}; do
            pushd $path
            fuzz_list=$(cargo fuzz list)
            for fuzz in $fuzz_list; do
                if [[ $fuzz =~ "afl" ]]; then
                    continue
                fi
                if [[ `ls -A fuzz/corpus/$fuzz | wc -l` -le 1 || \
                        "`find fuzz/corpus/$fuzz -name '*leak*'`" != "" || \
                        "`find fuzz/corpus/$fuzz -name '*timeout*'`" != "" || \
                        "`find fuzz/corpus/$fuzz -name '*crash*'`" != ""  ]]; then
                    echo "Test Case: $path - $fuzz fail"
                    check_total_result=`expr $check_total_result + 1`
                else
                    echo "Test Case: $path - $fuzz pass"
                fi
            done
            popd
        done
    else
        for path in ${fuzz_folder[@]};do
            pushd $path
            fuzz_list=$(cargo fuzz list)
            for fuzz in $fuzz_list;do
                if [[ "$fuzz" =~ "afl" ]];then
					queue_seed_num=`ls -A fuzz/artifacts/$fuzz/default/queue | wc -l`
                    if [[ $queue_seed_num -le 1 || \
                            "`ls -A fuzz/artifacts/$fuzz/default/crashes`" != "" || \
                            "`ls -A fuzz/artifacts/$fuzz/default/hangs`" != "" ]]; then
						echo "Test Case: $path - $fuzz fail"
                        check_total_result=`expr $check_total_result + 1`
					else
						echo "Test Case: $path - $fuzz pass"
                    fi
                else
                    continue
                fi
            done
            popd
        done
    fi

    if [[ $check_total_result -ne 0 ]]; then
        exit 1
    fi
}

main() {
    export AFL_NO_AFFINITY=1
    if [[ ! $PWD =~ td-shim$ ]]; then
        pushd ..
    fi
    test_check
   
	if [ "$check_build" == "YES" ]; then
		check_build
	else
		echo $test_case | grep "_all$"
		if [ $? == "0" ];then
			if [[ "$test_case" != "afl_all" && "$test_case" != "libfuzzer_all" ]];then
				show_prompt_info
                exit 1
			else
				run_all_case
				check_test_result
			fi
		else
			search_test_case
			run_single_case
		fi
    fi
}

main