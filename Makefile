obj-m += selinux-permissive.o
KDIR ?= /home/garcia/rtk2841
ARCH ?= arm
CROSS_COMPILE ?= /home/garcia/gcc-linaro-4.9-2014.11-x86_64_arm-eabi/bin/arm-none-eabi-

all:
	$(MAKE) -C $(KDIR) M=$(PWD) ARCH=$(ARCH) CROSS_COMPILE=$(CROSS_COMPILE) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) ARCH=$(ARCH) clean
