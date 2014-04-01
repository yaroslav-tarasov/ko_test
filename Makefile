#################################################
#
#
# Pre pre pre pre pre pre pre pre alpha
#
#
################################################## 
CC = gcc
CURRENT = $(shell uname -r)
KDIR = /lib/modules/$(CURRENT)/build
PWD = $(shell pwd)
DEST = /lib/modules/$(CURRENT)/misc
#EXTRA_CFLAGS += -O3 -std=gnu99 --no-warnings

TARGET = skb_filter_ko
OBJS = skb_filter.o nl_int.o 

obj-m := $(TARGET).o 
$(TARGET)-objs := $(OBJS)

all: default cmd

default:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

$(TARGET).o: $(OBJS)
	$(LD) -r -o $@ $(OBJS)

cmd:    netlink_cmd.c
	$(CC) netlink_cmd.c -o netlink_cmd  -lnl  


clean:
	@rm -f *.o .*.cmd .*.flags *.mod.c *.order
	@rm -f .*.*.cmd *.symvers *~ *.*~ TODO.*
	@rm -fR .tmp*
	@rm -rf .tmp_versions
