@VALGRIND_CHECK_RULES@

AUTOMAKE_OPTIONS = foreign -Wall
AM_CFLAGS=$(MY_CFLAGS) -I$(top_srcdir) -I$(top_srcdir)/mmap
if HAVE_GGHLITE
AM_CFLAGS+=-I$(includedir)/oz
endif

AM_LDFLAGS = $(top_builddir)/mmap/libmmap.la -lm

check_PROGRAMS = test_mmap test_mmap_mat write_encoding

TESTS = $(check_PROGRAMS)

test_mmap_SOURCES = test_mmap.c utils.c
test_mmap_mat_SOURCES = test_mmap_mat.c utils.c
write_encoding_SOURCES = write_encoding.c

all: $(TESTS)
