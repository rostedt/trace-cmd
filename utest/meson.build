# SPDX-License-Identifier: GPL-2.0
#
# Copyright (c) 2023 Daniel Wagner, SUSE LLC

sources = [
    'tracecmd-utest.c',
    'trace-utest.c',
]

e = executable(
   'trace-utest',
   sources,
   include_directories: [
       incdir,
       libtracecmd_incdir,
       libtracecmd_private_incdir,
       libtracecmd_ext_incdir],
   dependencies: [
       libtraceevent_dep,
       libtracefs_dep,
       zlib_dep,
       libzstd_dep,
       cunit_dep],
   link_with: [static_libtracecmd])

test('trace-utest', e)
