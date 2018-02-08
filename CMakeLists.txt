cmake_minimum_required(VERSION 3.2 FATAL_ERROR)
project(mmap VERSION 1.0.0 LANGUAGES C)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif(NOT CMAKE_BUILD_TYPE)
message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")

include(GNUInstallDirs)

option(HAVE_GGHLITE "Define whether gghlite is enabled" ON)
set(MMAP_HAVE_GGHLITE ${HAVE_GGHLITE})
message(STATUS "GGHLite: ${MMAP_HAVE_GGHLITE}")

set(mmap_SOURCES
  mmap/mmap_clt.c
  mmap/mmap_clt_pl.c
  mmap/mmap_dummy.c
  mmap/mmap_enc_mat.c
  )
set(mmap_HEADERS
  mmap/mmap.h
  mmap/mmap_clt.h
  mmap/mmap_clt_pl.h
  mmap/mmap_dummy.h
  )
if(MMAP_HAVE_GGHLITE)
  list(APPEND mmap_SOURCES mmap/mmap_gghlite.c)
  list(APPEND mmap_HEADERS mmap/mmap_gghlite.h)
endif(MMAP_HAVE_GGHLITE)

add_library(mmap SHARED ${mmap_SOURCES})
target_include_directories(mmap INTERFACE
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/mmap>
  $<INSTALL_INTERFACE:include/mmap>)
target_link_libraries(mmap PUBLIC gmp clt13 aesrand)
if(MMAP_HAVE_GGHLITE)
  target_link_libraries(mmap PUBLIC gghlite flint)
endif(MMAP_HAVE_GGHLITE)

include(FindOpenMP)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -Wpedantic -Werror -Wno-unused-result -std=gnu11 -march=native ${OpenMP_C_FLAGS}")
set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -pg -ggdb -O0")
set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -O3")
target_link_libraries(mmap INTERFACE "${OpenMP_C_FLAGS}")

install(TARGETS mmap LIBRARY DESTINATION lib)
install(FILES ${mmap_HEADERS} DESTINATION include/mmap)

# Test files

enable_testing()
macro(add_test_ _name)
  add_executable("${_name}" "tests/${_name}.c" "tests/utils.c")
  target_include_directories("${_name}" PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_SOURCE_DIR})
  target_link_libraries("${_name}" PRIVATE mmap gmp aesrand)
  if(MMAP_HAVE_GGHLITE)
    target_link_libraries("${_name}" PRIVATE flint)
  endif(MMAP_HAVE_GGHLITE)
  add_test(NAME "${_name}" COMMAND "${_name}")
endmacro()

add_test_(test_mmap)
# add_test_(test_mmap_mat)
