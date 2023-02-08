# SPDX-License-Identifier: GPL-2.0
#
# Copyright (c) 2023 Daniel Wagner, SUSE LLC

want_python = get_option('python')
if want_python != 'false'
    python3 = import('python').find_installation('python3')
    py3_dep = python3.dependency(required: want_python == 'true')
    swig = find_program('swig', required: want_python == 'true')
    header_found = cc.has_header('Python.h', dependencies: py3_dep)
    have_python_support = py3_dep.found() and swig.found() and header_found
else
    have_python_support = false
endif

if have_python_support
    pymod_swig = custom_target(
        'ctracecmd.py',
        input:   ['ctracecmd.i'],
        output:  ['ctracecmd.py', 'ctracecmd_wrap.c'],
        command: [
            swig,
            '-python',
            '-I' + meson.current_source_dir() + '/../include/trace-cmd',
            '-I' + libtraceevent_dep.get_pkgconfig_variable('prefix') + '/include/traceevent',
            '-o', '@OUTPUT1@',
            '@INPUT0@'],
        install: true,
        install_dir: [ python3.get_install_dir(pure: false, subdir: 'trace-cmd'), false])

    incdir_py = include_directories(['.', '../include/trace-cmd'])

    pyctracecmd_clib = python3.extension_module(
        '_ctracecmd',
        pymod_swig[1],
        dependencies : [libtraceevent_dep, libtracefs_dep, py3_dep],
        include_directories: [incdir, incdir_py],
        install: true,
        subdir: 'trace-cmd')
endif
