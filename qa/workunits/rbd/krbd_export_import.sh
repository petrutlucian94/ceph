#!/usr/bin/env bash
set -eEx

# This test performs the following steps:
#
# * creates an image file
# * imports it and then maps it
# * imports the mapped device and validates the content
# * create a new blank image, maps it and then exports the image to it,
#   validating its content.
# * checks unsupported operations:
#   * v2 exports/imports to/from raw block devices
#   * diff exports/imports to/from raw block devices

CEPH_SECRET_FILE=${CEPH_SECRET_FILE:-}
CEPH_ID=${CEPH_ID:-admin}
SECRET_ARGS=''
if [ ! -z $CEPH_SECRET_FILE ]; then
    SECRET_ARGS="--secret $CEPH_SECRET_FILE"
fi

TMP_FILES="/tmp/img1 /tmp/img1.export"

function expect_false() {
    if "$@"; then return 1; else return 0; fi
}

# /sys/bus/rbd/devices/ subdir
function get_device_dir {
    local POOL=$1
    local SNAP=$3
    local IMAGE=$2

    rbd device list | tail -n +2 | egrep "\s+$POOL\s+$IMAGE\s+$SNAP\s+" |
        awk '{print $1;}'
}

function get_device_path {
    local POOL=$1
    local IMAGE=$2
    local SNAP=$3
    rbd device list | tail -n +2 | egrep "\s+$POOL\s+$IMAGE\s+$SNAP\s+" |
        awk '{print $5;}'
}

function clean_mapping {
    local POOL=$1
    local IMAGE=$2
    if [[ $(get_device_path $POOL $IMAGE) ]]; then
        sudo rbd device unmap $POOL/$IMAGE
    fi
}

function clean_image {
    local IMAGE=$1
    rbd ls | grep $IMAGE > /dev/null && rbd rm $IMAGE || true
}

function clean_up {
    clean_mapping rbd testimg1
    clean_mapping rbd testimg1.export

    clean_image testimg1
    clean_image testimg1.export
    clean_image testimg1.import
    clean_image testimg1.import2

    sudo rm -f $TMP_FILES
}

clean_up

trap clean_up INT TERM EXIT

# create an image
dd if=/bin/sh of=/tmp/img1 bs=1k count=1 seek=10
dd if=/bin/dd of=/tmp/img1 bs=1k count=10 seek=100
dd if=/bin/rm of=/tmp/img1 bs=1k count=100 seek=1000
dd if=/bin/ls of=/tmp/img1 bs=1k seek=10000
dd if=/bin/ln of=/tmp/img1 bs=1k seek=100000
dd if=/dev/zero of=/tmp/img1 count=0 seek=151552 # 74MB

# import
rbd import /tmp/img1 testimg1
sudo rbd info testimg1
sudo rbd device map testimg1 --id $CEPH_ID $SECRET_ARGS

DEV_ID1=$(get_device_dir rbd testimg1 -)
DEV_PATH1=$(get_device_path rbd testimg1 -)
echo "dev_id1 = $DEV_ID1"
cat /sys/bus/rbd/devices/$DEV_ID1/size
cat /sys/bus/rbd/devices/$DEV_ID1/size | grep 77594624

sudo cmp /tmp/img1 $DEV_PATH1

# create and map a new empty image
rbd create testimg1.export --size=74M
sudo rbd device map testimg1.export --id $CEPH_ID $SECRET_ARGS

DEV_ID2=$(get_device_dir rbd testimg1.export -)
DEV_PATH2=$(get_device_path rbd testimg1.export -)
echo "dev_id2 = $DEV_ID2"
cat /sys/bus/rbd/devices/$DEV_ID2/size
cat /sys/bus/rbd/devices/$DEV_ID2/size | grep 77594624

# export the first image to a block device (the second mounted image).
sudo rbd export testimg1 $DEV_PATH2

sudo cmp -n 77594624 /tmp/img1 $DEV_PATH2

# import the raw block device
sudo rbd import $DEV_PATH2 testimg1.import
# export it back to a file so that we may check its content
sudo rbd export testimg1.import /tmp/img1.export
sudo cmp -n 77594624 /tmp/img1 /tmp/img1.export

# Test unsupported operations
# v2 exports with raw block devices
expect_false sudo rbd export --export-format=2 testimg1 $DEV_PATH2
expect_false sudo rbd import --export-format=2 $DEV_PATH2 testimg1.import2

# diffs with raw block devices
expect_false sudo rbd export-diff testimg1 $DEV_PATH2
expect_false sudo rbd import-diff $DEV_PATH2 testimg1.import2

echo OK
