AUTOMAKE_OPTIONS = foreign -Wall
AM_CFLAGS  = ${DEBUG_CFLAGS} -I$(top_srcdir) -I$(top_srcdir)/dgs -I$(top_srcdir)/mmap

AM_LDFLAGS = \
	$(top_builddir)/mmap/libmmap.la

check_PROGRAMS = test_mmap test_mmap_mat write_encoding

TESTS = $(check_PROGRAMS)

test_mmap_SOURCES = test_mmap.c utils.c
test_mmap_LDADD   = -lm
test_mmap_INCLUDEDIR = $(includedir)/oz $(includedir)/gghlite

test_mmap_mat_SOURCES = test_mmap_mat.c utils.c
test_mmap_mat_LDADD   = -lm
test_mmap_mat_INCLUDEDIR = $(includedir)/oz $(includedir)/gghlite

test_write_encoding_SOURCES = write_encoding.c
test_write_encoding_LDADD = -lm
test_write_encoding_INCLUDEDIR = $(includedir)/oz $(includedir)/gghlite
