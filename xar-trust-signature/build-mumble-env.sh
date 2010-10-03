#!/bin/bash
make CC="${CC}" CFLAGS="-std=c99 ${OSX_CFLAGS} -I${MUMBLE_PREFIX}/include/" LDFLAGS="${OSX_LDFLAGS} -L${MUMBLE_PREFIX}/lib/"
