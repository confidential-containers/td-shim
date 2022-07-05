#!/bin/bash
#
# Copyright (c) 2022 Intel Corporation
#
# SPDX-License-Identifier: Apache-2.0
#

fuzz_folder=(
    "td-loader"
    "td-uefi-pi"
    "td-shim"
)

show_prompt_info() {
    echo "Usage:"
    echo "  -c Test case name, e.g. afl_pe, afl_all, libfuzzer_all"
    echo "  -t Excution time, default is 3600"
	echo "  -b Build all test case for check"
	echo ""
	echo "Example:"
    echo "Run single test case:    bash fuzzing.sh -c afl_pe -t 3600"
	echo "Run all test case:       bash fuzzing.sh -c afl_all -t 3600"
}

while getopts ':c:t:bh' OPT; do
    case $OPT in
        c) test_case="$OPTARG";;
        t) test_time="$OPTARG";;
		b) check_build="YES";;
        h) show_prompt_info;;
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
        export RUSTFLAGS="-C instrument-coverage"
        export LLVM_PROFILE_FILE="fuzz-%p-%m.profraw"
        find . -name "*.profraw" | xargs rm -rf

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
            
            if [ -d "${test_case}_cov" ]; then
                rm -rf "${test_case}_cov"
            fi
            grcov . -s src --binary-path fuzz/target/debug/$test_case -t html --branch --ignore-not-existing -o "${test_case}_cov"
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
        timeout $test_time cargo fuzz run $test_case

        if [ ! -d "${test_case}_fuzz_cov" ]; then
            rm -rf ${test_case}_fuzz_cov
        fi
        find . -name "*.profraw" | xargs rm -rf
        cargo fuzz coverage $test_case
        grcov . -s src -b fuzz/target/x86_64-unknown-linux-gnu/release/$test_case -t html --branch --ignore-not-existing -o "${test_case}_fuzz_cov"
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
                timeout $test_time cargo fuzz run $fuzz
                
                if [ ! -d "${fuzz}_fuzz_cov" ]; then
                    rm -rf ${fuzz}_fuzz_cov
                fi
                find . -name "*.profraw" | xargs rm -rf
                cargo fuzz coverage $fuzz
                grcov . -s src -b fuzz/target/x86_64-unknown-linux-gnu/release/$fuzz -t html --branch --ignore-not-existing -o "${fuzz}_fuzz_cov"
            done
            popd
        done
    else
        for path in ${fuzz_folder[@]};do
            pushd $path
            fuzz_list=$(cargo fuzz list)
            for fuzz in $fuzz_list;do
                if [[ "$fuzz" =~ "afl" ]];then
                    export RUSTFLAGS="-C instrument-coverage"
                    export LLVM_PROFILE_FILE="fuzz-%p-%m.profraw"
                    find . -name "*.profraw" | xargs rm -rf

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

                        if [ -d "${fuzz}_cov" ]; then
                            rm -rf "${fuzz}_cov"
                        fi
                        grcov . -s src --binary-path fuzz/target/debug/$fuzz -t html --branch --ignore-not-existing -o "${fuzz}_cov"
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
	if [ "$test_case" == "libfuzzer_all" ];then
        for path in ${fuzz_folder[@]}; do
            pushd $path
            fuzz_list=$(cargo fuzz list)
            for fuzz in $fuzz_list; do
                if [[ $fuzz =~ "afl" ]]; then
                    continue
                fi
				if [[ "`find fuzz/corpus/$fuzz -name '*leak*'`" != "" || "`find fuzz/corpus/$fuzz -name '*timeout*'`" != "" || "`find fuzz/corpus/$fuzz -name '*crash*'`" != ""  ]]; then
					echo "Test Case: $path - $fuzz fail"
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
                    if [[ $queue_seed_num -le 1 || "`ls -A fuzz/artifacts/$fuzz/default/crashes`" != "" || "`ls -A fuzz/artifacts/$fuzz/default/hangs`" != "" ]]; then
						echo "Test Case: $path - $fuzz fail"
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

}

main() {
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