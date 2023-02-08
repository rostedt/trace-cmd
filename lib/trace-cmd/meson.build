# SPDX-License-Identifier: LGPL-2.1
#
# Copyright (c) 2023 Daniel Wagner, SUSE LLC

sources = [
    'trace-hash.c',
    'trace-hooks.c',
    'trace-input.c',
    'trace-output.c',
    'trace-recorder.c',
    'trace-util.c',
    'trace-filter-hash.c',
    'trace-filter.c',
    'trace-msg.c',
    'trace-plugin.c',
    'trace-maps.c',
    'trace-timesync.c',
    'trace-timesync-ptp.c',
    'trace-compress.c',
    'trace-blk-hack.c',
    'trace-ftrace.c',
]

if perf_defined
    sources += 'trace-perf.c'
endif

if vsock_defined
    sources += 'trace-timesync-kvm.c'
endif

if zlib_dep.found()
    sources += 'trace-compress-zlib.c'
endif

if libzstd_dep.found()
    sources += 'trace-compress-zstd.c'
endif

if libtracecmd_standalone_build
    libtracecmd = library(
        'tracecmd',
        sources,
        version: library_version,
        dependencies: [
            libtraceevent_dep,
            libtracefs_dep,
            zlib_dep,
            libzstd_dep,
            audit_dep],
        include_directories: [
            libtracecmd_incdir,
            libtracecmd_private_incdir,
            libtracecmd_ext_incdir],
        install: true)

    pkg = import('pkgconfig')
    pkg.generate(
        libtracecmd,
        subdirs: 'trace-cmd',
        libraries: [
            libtracefs_dep,
            libtraceevent_dep],
        filebase: meson.project_name(),
        name: meson.project_name(),
        version: meson.project_version(),
        description: 'Library for creating and reading trace-cmd data files',
        url: 'https://git.kernel.org/pub/scm/utils/trace-cmd/trace-cmd.git/')

    libtracecmd_dep = declare_dependency(
       include_directories: ['.'],
       link_with: libtracecmd)
else
    static_libtracecmd = static_library(
        'tracecmd',
        sources,
        dependencies: [
            libtraceevent_dep,
            libtracefs_dep,
            zlib_dep,
            libzstd_dep,
            audit_dep],
        include_directories: [
            libtracecmd_incdir,
            libtracecmd_private_incdir,
            libtracecmd_ext_incdir],
        install: false)
endif
