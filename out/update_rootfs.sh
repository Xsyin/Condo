#!/bin/bash

CURDIR=`pwd`
MOUNTDIR_ROOTFS=/media/$USER/rootfs
MOUNTDIR_BOOT=/media/$USER/boot


update()
{
	sudo losetup --partscan /dev/loop41 $1
	sudo mount /dev/loop41p1 $MOUNTDIR_BOOT
	sudo mount /dev/loop41p2 $MOUNTDIR_ROOTFS
	#sudo cp Image $MOUNTDIR_BOOT
	# sudo cp ../hello.ko $MOUNTDIR_ROOTFS
	# sudo cp ../ns $MOUNTDIR_ROOTFS
	# sleep 2
	# sync
	# sudo umount $MOUNTDIR_BOOT
	# sudo umount $MOUNTDIR_ROOTFS
	# sudo losetup -d /dev/loop41

}


help()
{
	echo "update rootfs. mount rootfs.wic on /dev/loop20, make sure /dev/loop20 is not busy"
	echo "default mount /dev/loop20p1 on /media/$USER/boot, mount /dev/loop20p2 on /media/$USER/rootfs"
	echo "for example: ./update_rootfs.sh _rootfs.wic"
}

arg_num=$#
if [ ${arg_num} -eq 0 ]
then
	help
	exit 0
fi

if [ "$1" == "help" ]
then
	help
	exit 0
fi

update $1

