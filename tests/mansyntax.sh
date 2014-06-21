#!/bin/sh
set -e

# Written by Mikhail Gusarov
#
# Run syntax checks for all manpages in the documentation tree.
#

srcdir="`cd $(dirname $0);pwd`"
mandir=${srcdir}/../docs

#
# Only test if suitable man is available
#
if ! man --help | grep -q warnings; then
  exit 77
fi

ec=0

trap "rm -f $srcdir/man3" EXIT

ln -sf "$mandir" "$srcdir/man3"

echo MANDIR
echo $mandir
echo $mandir/libssh2_*.*
echo $mandir/libssh2_*
echo ${mandir}/libssh2_*.*
echo MANDIR2
mandir2=docs
echo $mandir2
echo $mandir2/libssh2_*.*
echo $mandir2/libssh2_*
echo ${mandir2}/libssh2_*.*

for manpage in $mandir/libssh2_*.*; do
  echo "$manpage"
  warnings=$(LANG=en_US.UTF-8 MANWIDTH=80 man -M "$srcdir" --warnings \
    -E UTF-8 -l "$manpage" 2>&1 >/dev/null)
  if [ -n "$warnings" ]; then
    echo "$warnings"
    ec=1
  fi
done

exit $ec
