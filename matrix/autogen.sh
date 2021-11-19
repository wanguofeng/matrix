#!/bin/bash

export STAGING_DIR=

CUR_DIR=$(pwd)

if [ -z $ROOT_DIR ];then
    TARGET_PLATFORM=host
    cd $(dirname $BASH_SOURCE)
    PROJECT_DIR=$(dirname `echo $(pwd)/$(basename $BASH_SOURCE)`)
    echo "project = $PROJECT_DIR"
    ROOT_DIR=`echo ${PROJECT_DIR%/platform*}`
    echo "root dir = $ROOT_DIR"
    export ROOT_DIR=$ROOT_DIR
fi

if [ -z $TARGET_PLATFORM ];then
    TARGET_PLATFORM=host
fi

cd $ROOT_DIR

RELATED_PATH=.


if [ $# == 0 ];then
    echo "No parameters";
else
    echo "带了$#个参数"
    target_path=`echo $1 | sed "s/\// /g"`
    target_path=`echo $target_path| awk 'NR==1{print $NF}'`
    if [ -d ./$1 ]
    then
        cd $1
	source $ROOT_DIR/config/$target_path.sh
        ret_value=$?
        if [ "$ret_value" != "0" ]; then
            echo "************************** build submodule $1 error *********************"
        else
            echo "-------------------------- build submodule $1 success--------------------"
        fi
        cd $ROOT_DIR
    else
        echo "------------------------- $1 is not exist --------------------"
    fi
fi

exec /bin/bash
