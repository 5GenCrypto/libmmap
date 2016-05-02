AUTOMAKE_OPTIONS = foreign -Wall
AM_CFLAGS  = ${DEBUG_CFLAGS}

lib_LTLIBRARIES=libmmap.la

libmmap_la_SOURCES = mmap_clt.c mmap_gghlite.c mmap_enc_mat.c
libmmap_la_LDFLAGS = -release 0.0.$(RELEASE) -no-undefined
libmmap_la_LIBADD = -lgghlite -ldgsl

pkgincludesubdir = $(includedir)/src
pkgincludesub_HEADERS = mmap.h mmap_clt.h mmap_gghlite.h
