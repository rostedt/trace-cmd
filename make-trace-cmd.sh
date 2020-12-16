#!/bin/bash

if [ -z "$INSTALL_PATH" ]; then
	echo
	echo 'Error: No $INSTALL_PATH defined'
	echo
	echo "   usage: [PREFIX=prefix][BUILD_PATH=/path/to/build] INSTALL_PATH=/path/to/install make-trace-cmd.sh install|install_libs|clean|uninstall"
	echo
	echo "     Used to create a self contained directory to copy to other machines."
	echo
	echo "   Please read PACKAGING for more information."
	echo
	exit
fi

if [ ! -d $INSTALL_PATH ]; then
	mkdir $INSTALL_PATH
fi

if [ ! -z "$BUILD_PATH" ]; then
	if [ ! -d $BUILD_PATH ]; then
		mkdir $BUILD_PATH
	fi
	O_PATH="O=$BUILD_PATH"
fi

if [ -z "$PREFIX" ]; then
	PREFIX="/usr"
fi

PKG_CONFIG="pkg-config --with-path $INSTALL_PATH/usr/lib64/pkgconfig --define-variable=prefix=$INSTALL_PATH/$PREFIX" CFLAGS="-g -Wall -I$INSTALL_PATH/$PREFIX/include" make DESTDIR=$INSTALL_PATH  $O_PATH prefix=$PREFIX $@
