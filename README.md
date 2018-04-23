# GuardION
This software is the open-source component of our paper "GuardION: Practical Mitigation of DMA-based Rowhammer Attacks on ARM", published in the Conference on Detection of Intrusions and Malware & Vulnerability Assessment (DIMVA) 2018.  It allows you to patch an Android kernel so that DMA allocations are guarded with empty rows, resulting in the isolation of bitflips and thus mitigation of Drammer-like attacks.

The code is released under the [Apache 2.0 license](https://github.com/vusec/guardion/blob/master/LICENSE).

This repository does *not* contain any exploit code for our RAMpage exploit.

# **Disclaimer**
**If, for some weird reason, you think running this code broke your device, you get to keep both pieces.**

# Patches
All code was compiled and tested on a Google Pixel, running Android 7.1.1 (Nougat), with kernel version 3.18: `android-7.1.1_r0.5 / android-msm-marlin-3.18-nougat-mr1 Pixel XL (marlin) / Pixel (sailfish)`. The makefiles assume that you have an ARM64 sysroot install of the Android NDK (version r11c) in `/opt/android-ndk-r11c/sysroot-arm64/`. For more information on how to obtain such sysroot, have a look at the [Drammer README](https://github.com/vusec/drammer/blob/master/README.md).

A typical example of how to install our patches:

    cd ~
    git clone https://android.googlesource.com/kernel/msm
    cd msm
    git checkout -b android-msm-marlin-3.18-nougat-mr1 origin/android-msm-marlin-3.18-nougat-mr1

    export CROSS_COMPILE=/opt/android-ndk-r11c/sysroot-arm64/bin/aarch64-linux-android-
    export ARCH=arm64

    make marlin_defconfig
    make -j6
    # Run make menuconfig to enable loadable kernel module support if you want to compile nohammer (see below).
    # (make sure to also enable "Module unloading")

    # This should result in a compiled kernel, we can now apply our patches and recompile:
    cd ~/msm
    cp /path/to/guardion/ion/isolation.patch .
    cp /path/to/guardion/bitmap/bitmap.patch .
    git apply -v isolation.patch
    make -j6

## bitmap
The patch in `bitmap/` enables isolation of DMA memory that uses the bitmap (used by ION CMA heap)

## ion
The patches in `ion/` enables isolation for the regular ION heaps. `isolation-debug.patch` adds some debug prints that were used to measure the memory use at run-time.

## nohammer
The files in `nohammer/` hold our attempt at implementing *nohammer*, as proposed by Pavel Machek at the [kernel harderning mailinglist](https://lwn.net/Articles/704926/). Note that our experiences with this approach were not very positive (the device would become unresponsive). Not all of the provided code may work and may require some additional changes.
