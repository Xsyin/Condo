#!/bin/bash

CURDIR=`pwd`
MOUNTDIR=/media/$USER/rootfs

sudo umount /media/$USER/boot
sudo umount $MOUNTDIR
sudo losetup -d /dev/loop41


