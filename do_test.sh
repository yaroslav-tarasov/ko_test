#!/bin/bash

make && {
rmmod bf_filter
insmod bf_filter.ko 
#lsmod 
#dmesg
}

