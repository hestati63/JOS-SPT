#!/bin/bash
IMAGE=cs492-virt
BASE=$( dirname $(readlink -nf "$0") )/JOS-SPT
[ ! -z $(docker images -q $IMAGE) ] || docker build -t $IMAGE .
docker run --name virt --rm \
           --privileged -v $BASE:/virt -e UID=`id -u` -e USER=$USER -it $IMAGE
