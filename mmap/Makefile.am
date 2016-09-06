lib_LTLIBRARIES=libmmap.la

libmmap_la_LDFLAGS = -no-undefined -version-info 0:0:0
libmmap_la_CFLAGS = $(COMMON_CFLAGS) $(EXTRA_CFLAGS) -I$(top_srcdir) -fopenmp
libmmap_la_LIBADD = -lgomp

libmmap_la_SOURCES = mmap_clt.c mmap_gghlite.c mmap_dummy.c mmap_enc_mat.c

pkgincludesubdir = $(includedir)/mmap
pkgincludesub_HEADERS = mmap.h mmap_clt.h mmap_gghlite.h mmap_dummy.h
