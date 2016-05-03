AUTOMAKE_OPTIONS = foreign -Wall
AM_CFLAGS  = ${DEBUG_CFLAGS} -I$(top_srcdir)

lib_LTLIBRARIES=libmmap.la

libmmap_la_SOURCES = mmap_clt.c mmap_gghlite.c mmap_enc_mat.c
libmmap_la_LDFLAGS = -version-info $(LIBMMAP_VERSION) -no-undefined

pkgincludesubdir = $(includedir)/mmap
pkgincludesub_HEADERS = mmap.h mmap_clt.h mmap_gghlite.h
