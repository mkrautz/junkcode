#!/bin/bash
make CC="${CC}" CFLAGS="-std=c99 ${OSX_CFLAGS} -I${MUMBLE_PREFIX}/include/" LDFLAGS="${OSX_LDFLAGS} -L${MUMBLE_PREFIX}/lib/"
mkdir -p rel
cd rel
cp ../xar-trust-signature .
cp ../LICENSE .
files=`otool -L xar-trust-signature | grep ${MUMBLE_PREFIX} | sed 's, (compat.*,,' | sed 's,[	],,'`
for file in ${files}; do
	bfn=`basename ${file}`
	cp ${file} ${bfn}
	chmod 755 ${bfn}
	install_name_tool -id ${bfn} ${bfn}
	for chfile in ${files}; do
		bchfn=`basename ${chfile}`
		install_name_tool -change ${chfile} ${bchfn} ${bfn}
	done
	install_name_tool -change ${file} ${bfn} xar-trust-signature
done
cd ..
rm xar-trust-signature
mv rel xar-trust-signature
tar -cjpvf xar-trust-signature-macosx.tar.bz2 xar-trust-signature
rm -rf xar-trust-signature
