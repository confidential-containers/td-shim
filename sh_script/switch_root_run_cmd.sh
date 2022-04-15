#!/usr/bin/expect
spawn su root
expect "Password:"
send "1\r" # Change to you password
send "echo core >/proc/sys/kernel/core_pattern\r"
send "cd /sys/devices/system/cpu\r"
send "echo performance | tee cpu*/cpufreq/scaling_governor\r"
 
expect eof
exit 
