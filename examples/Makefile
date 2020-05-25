TOPDIR = ..
PROG = client.so
CSRCS = client.c

CFLAGS = -fPIC -O2 -I${TOPDIR}/include -fvisibility=hidden
LDFLAGS = -shared --whole-archive ${TOPDIR}/runtime/runtime.a --no-whole-archive

include ${TOPDIR}/make/comm.mk
include ${TOPDIR}/make/c.mk
include ${TOPDIR}/user.mk

${PROG}: ${TOPDIR}/runtime/runtime.a
