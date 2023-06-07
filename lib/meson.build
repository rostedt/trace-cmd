# SPDX-License-Identifier: LGPL-2.1
#
# Copyright (c) 2023 Daniel Wagner, SUSE LLC

project(
    'libtracecmd', ['c'],
    meson_version: '>= 0.50.0',
    license: 'GPL-2.0',
    version: '1.4.0',
    default_options: [
        'c_std=gnu99',
        'buildtype=debug',
        'default_library=both',
        'prefix=/usr/local',
        'warning_level=1'])

cc = meson.get_compiler('c')

prefixdir = get_option('prefix')
mandir    = join_paths(prefixdir, get_option('mandir'))
htmldir   = join_paths(prefixdir, get_option('htmldir'))

libtracecmd_standalone_build = true

library_version = meson.project_version()

conf = configuration_data()

libtraceevent_dep = dependency('libtraceevent', version: '>= 1.5.0', required: true)
libtracefs_dep = dependency('libtracefs', version: '>= 1.6.0', required: true)

zlib_dep = dependency('zlib', required: false)
conf.set('HAVE_ZLIB', zlib_dep.found(), description: 'Is zlib avialable?')

libzstd_dep = dependency('libzstd', version: '>= 1.4.0', required: false)
conf.set('HAVE_ZSTD', libzstd_dep.found(), description: 'Is libzstd available?')

cunit_dep = dependency('cunit', required : false)

vsock_defined = get_option('vsock') and cc.has_header('linux/vm_sockets.h')
conf.set('VSOCK', vsock_defined, description: 'Is vsock available?')

perf_defined = cc.has_header('linux/perf_event.h')
conf.set('PERF', perf_defined, description: 'Is perf available?')

have_ptrace = get_option('ptrace') and cc.compiles(
    '''
    #include <stdio.h>
    #include <sys/ptrace.h>

    int main (void)
    {
            int ret;
            ret = ptrace(PTRACE_ATTACH, 0, NULL, 0);
            ptrace(PTRACE_TRACEME, 0, NULL, 0);
            ptrace(PTRACE_GETSIGINFO, 0, NULL, NULL);
            ptrace(PTRACE_GETEVENTMSG, 0, NULL, NULL);
            ptrace(PTRACE_SETOPTIONS, NULL, NULL,
                           PTRACE_O_TRACEFORK |
                           PTRACE_O_TRACEVFORK |
                           PTRACE_O_TRACECLONE |
                           PTRACE_O_TRACEEXIT);
            ptrace(PTRACE_CONT, NULL, NULL, 0);
            ptrace(PTRACE_DETACH, 0, NULL, NULL);
            ptrace(PTRACE_SETOPTIONS, 0, NULL,
                   PTRACE_O_TRACEFORK |
                   PTRACE_O_TRACEVFORK |
                   PTRACE_O_TRACECLONE |
                   PTRACE_O_TRACEEXIT);
            return ret;
    }
    ''',
    name: 'ptrace')
if not have_ptrace
    conf.set10('NO_PTRACE', true, description: 'Is ptrace missing?')
    conf.set('WARN_NO_PTRACE', true, description: 'Issue no ptrace warning?')
endif

audit_dep = dependency('audit', required: false)
if not audit_dep.found()
    conf.set10('NO_AUDIT', true, description: 'Is audit missing?')
    conf.set('WARN_NO_AUDIT', true, description: 'Issue no audit warning?')
endif

add_project_arguments(
    [
        '-D_GNU_SOURCE',
        '-include', 'trace-cmd/include/private/config.h',
    ],
    language : 'c')

libtracecmd_ext_incdir = include_directories(
    [
        '../include',
        '../include/trace-cmd',
        '../tracecmd/include'
    ])

subdir('trace-cmd/include')
subdir('trace-cmd/include/private')
subdir('trace-cmd')
if libtracecmd_standalone_build
    subdir('Documentation/libtracecmd')

    custom_target(
        'docs',
        output: 'docs',
        depends: [html, man],
        command: ['echo'])
endif

install_headers(
    '../include/trace-cmd/trace-cmd.h',
     subdir: 'trace-cmd')
