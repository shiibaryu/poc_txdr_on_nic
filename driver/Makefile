KERNELSRCDIR := /lib/modules/$(shell uname -r)/build
BUILD_DIR := $(shell pwd)
VERBOSE = 0

obj-m := nettlp_mnic.o
nettlp_mnic-objs:= nettlp_mnic_kernel.o nettlp_msg.o

ccflags-y := -I$(src)/../include/

all:
	make -C $(KERNELSRCDIR) M=$(BUILD_DIR) V=$(VERBOSE) modules

clean:
	make -C $(KERNELSRCDIR) M=$(BUILD_DIR) clean

