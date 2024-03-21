MODULE := smzy
FILES := inode.o main.o avc.o smzy-core.o scontext-resolution.o\
			 ac-admin.o ac-sensitive.o ac-private.o ac-software.o

LINUX_SRC := /root/workspace/kernel/linux
#LINUX_SRC := $(srctree)

ifdef KERNELRELEASE 

CFLAGS_scontext-resolution.o := -I$(LINUX_SRC)/security/selinux/ -I$(LINUX_SRC)/security/selinux/include


obj-m += $(MODULE).o
$(MODULE)-m := $(FILES)

else

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

test:
	insmod $(MODULE).ko
	rmmod $(MODULE)

endif
