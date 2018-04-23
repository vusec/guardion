KERNEL  = $(HOME)/msm
MODULE  = marlin
OBJECTS = nohammer.o

HEADERS     = $(wildcard include/*.h)
MCFLAGS     = -I$(PWD)/../user -DARM8

obj-m := $(MODULE).o
$(MODULE)-objs := $(OBJECTS)

all: $(MODULE).ko

$(MODULE).ko: $(HEADERS) $(patsubst %.o,%.c,$(OBJECTS))
	ARCH=arm64 CROSS_COMPILE=/opt/android-ndk-r11c/sysroot-arm64/bin/aarch64-linux-android- make -C $(KERNEL) M=$(PWD) modules EXTRA_CFLAGS="$(MCFLAGS)"

install:
	make clean all
	adb push $(MODULE).ko /sdcard/
	adb shell su -c "rmmod $(MODULE) || true"
	adb shell su -c "insmod /sdcard/$(MODULE).ko"

clean:
	make -C $(KERNEL) M=$(PWD) clean

