# SPDX-License-Identifier: GPL-2.0
#
# Copyright (c) 2023 Daniel Wagner, SUSE LLC

project(
    'trace-cmd', ['c'],
    meson_version: '>= 0.50.0',
    license: 'GPL-2.0',
    version: '3.2.0',
    default_options: [
        'c_std=gnu99',
        'buildtype=debug',
        'default_library=both',
        'prefix=/usr/local',
        'warning_level=1'])

cc = meson.get_compiler('c')

prefixdir = get_option('prefix')
datadir = join_paths(prefixdir, get_option('datadir'))
bindir = join_paths(prefixdir, get_option('bindir'))
mandir = join_paths(prefixdir, get_option('mandir'))
htmldir = join_paths(prefixdir, get_option('htmldir'))

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

config_h = configure_file(
    output: 'config.h',
    configuration: conf
)

version = meson.project_version().split('.')

vconf = configuration_data()
vconf.set('VERSION_CODE', version[0].to_int() * 256 + version[1].to_int())
vconf.set('EXTRAVERSION', '"@0@"'.format(version[2]))
vconf.set('FILE_VERSION', '""')
vconf.set('VERSION_STRING', '"@0@"'.format(meson.project_version()))

version_tag = get_option('version-tag')
if version_tag != ''
    vconf.set('VERSION_GIT', '"@0@"'.format(version_tag))
else
    r = run_command(
        'meson-vcs-tag.sh',
        meson.current_source_dir(),
        meson.project_version(),
        check: true)
    vconf.set('VERSION_GIT', '"@0@"'.format(r.stdout().strip()))
endif
version_h = configure_file(
    output: 'tc_version.h',
    configuration: vconf)

add_project_arguments(
    [
      '-D_GNU_SOURCE',
      '-include', 'config.h',
    ],
    language : 'c')

incdir = include_directories(['.', 'include'])

# libtracecmd: trace-cmd currently depends on a statically linked
# libtracecmd.  libtracecmd is sill very strongly coupled with
# trace-cmd (or the other way around). To reduce the development setup
# complexity we add some of the 'top meson.build' from libtracecmd and
# make it simpler to use.
library_version = '1.3.0'
libtracecmd_standalone_build = false
libtracecmd_ext_incdir = include_directories(
    [
        'include',
        'include/trace-cmd',
        'tracecmd/include'
    ])
subdir('lib/trace-cmd/include')
subdir('lib/trace-cmd/include/private')
subdir('lib/trace-cmd')

# trace-cmd
subdir('tracecmd')
subdir('python')
if cunit_dep.found()
    subdir('utest')
endif
subdir('Documentation/trace-cmd')

custom_target(
    'docs',
    output: 'docs',
    depends: [html, man],
    command: ['echo'])
