#!/bin/sh
##
## FILE: run.sh
##
## DESCRIPTION: Run Cmake Build
##

## Exit Point
die() {
	[ -n "$2" ] && echo "$2"
	exit $1
}

##
command -v cmake > /dev/null || die 78 'Required, cmake'

## Goto Directory
OWD="$PWD"
command -v readlink > /dev/null && {
    cd "$(dirname "$(readlink -f "$0")")"
    ## Git Bash Lacks Readlink
}

## Prepare Build Directory
mkdir build
cd build
cmake -DCMAKE_BUILD_TYPE=Release ..

## Begin Build
make
make package_source

cd "$OWD"


## Exit Jump
die 0
