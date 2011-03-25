WIN32_EXTRA_DIST=\
	sigar.rc.in \
	wmi.cpp

SIGAR_OS_SRCS=\
	peb.c \
	wmi_stubs.c \
	win32_sigar.c

SIGAR_OS_HDRS=\
	sigar_os.h \
	sigar_pdh.h

INCLUDES = @INCLUDES@

if OS_WIN32
noinst_LTLIBRARIES = libsigar_os.la

libsigar_os_la_SOURCES = ${SIGAR_OS_SRCS}

noinst_HEADERS = ${SIGAR_OS_HDRS}

EXTRA_DIST=${WIN32_EXTRA_DIST}

else

EXTRA_DIST=\
	${SIGAR_OS_SRCS} \
	${SIGAR_OS_HDRS} \
	${WIN32_EXTRA_DIST}
endif
