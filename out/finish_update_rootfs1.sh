#!/bin/bash

CURDIR=`pwd`
MOUNTDIR=/media/$USER/rootfs1

sudo umount /media/$USER/boot1
sudo umount $MOUNTDIR
sudo losetup -d /dev/loop40


