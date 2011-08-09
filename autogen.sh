#!/bin/sh -e
# Run this to generate all the initial makefiles, etc.

LIBTOOLIZE_FLAGS="--copy --force"
AUTOMAKE_FLAGS="--add-missing --copy"

ARGV0=$0
ARGS="$@"

run() {
	echo "$ARGV0: running \`$@' $ARGS"
	$@ $ARGS
}

# Seach a list of names for the first occurence of a program.
# Some systems may use aclocal-1.10, others may have aclocal etc.
#
# Exit with status code 0 if the program exists (and print the
# path to stdout), exit with status code 1 if it can't be
# located
find_program() {
  set +e
  for f in "$@"
  do
    file=`which ${f} 2>/dev/null | grep -v '^no '`
    if test -n "x${file}" -a -x "${file}"
    then
      echo ${file}
      set -e
      exit 0
    fi
  done

  echo "Failed to locate required program:" 1>&2
  echo "\t$@" 1>&2
  set -e
  exit 1
}

LIBTOOLIZE=`find_program libtoolize libtoolize-1.5 glibtoolize`
ACLOCAL=`find_program aclocal-1.11 aclocal-1.10 aclocal-1.9 aclocal`
AUTOMAKE=`find_program automake-1.11 automake-1.10 automake-1.9 automake`
AUTOCONF=`find_program autoconf autoconf259 autoconf-2.59`

run $LIBTOOLIZE $LIBTOOLIZE_FLAGS
run $ACLOCAL $ACLOCAL_FLAGS
run $AUTOMAKE $AUTOMAKE_FLAGS
run $AUTOCONF
test "$ARGS" = "" && echo "Now type './configure --enable-maintainer-mode ...' and 'make' to compile."

