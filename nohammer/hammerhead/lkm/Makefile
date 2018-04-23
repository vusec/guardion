KERNEL  = $(HOME)/msm
MODULE  = hammerhead
OBJECTS = nohammer.o

HEADERS     = $(wildcard include/*.h)
MCFLAGS     = -I$(PWD)/../user

obj-m := $(MODULE).o
$(MODULE)-objs := $(OBJECTS)

all: $(MODULE).ko

$(MODULE).ko: $(HEADERS) $(patsubst %.o,%.c,$(OBJECTS))
	ARCH=arm CROSS_COMPILE=/opt/android-ndk-r11c/sysroot-arm/bin/arm-linux-androideabi- make -C $(KERNEL) M=$(PWD) modules EXTRA_CFLAGS="$(MCFLAGS)"

install:
	make clean all
	adb push $(MODULE).ko /sdcard/
	adb shell su -c "rmmod $(MODULE) || true"
	adb shell su -c "insmod /sdcard/$(MODULE).ko"

clean:
	make -C $(KERNEL) M=$(PWD) clean

