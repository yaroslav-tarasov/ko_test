#!/bin/bash

make && {
rmmod skb_filter_ko
insmod skb_filter_ko.ko 
#lsmod 
dmesg
}

