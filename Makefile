TOPDIR = .
SUBDIRS = patcher runtime examples

include ${TOPDIR}/make/comm.mk
include ${TOPDIR}/user.mk

examples.all: runtime.all
