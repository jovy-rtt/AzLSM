obj-m:=azlsm.o
CONFIG_MODULE_SIG=n
CURRENT_PATH :=$(shell pwd)
VERSION_NUM :=$(shell uname -r)
LINUX_PATH :=/lib/modules/$(VERSION_NUM)/build

all :
	make -C $(LINUX_PATH) M=$(CURRENT_PATH) modules
clean :
	make -C $(LINUX_PATH) M=$(CURRENT_PATH) clean