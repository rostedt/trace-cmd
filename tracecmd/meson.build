# SPDX-License-Identifier: GPL-2.0
#
# Copyright (c) 2023 Daniel Wagner, SUSE LLC

sources = [
    'trace-agent.c',
    'trace-attach.c',
    'trace-check-events.c',
    'trace-clear.c',
    'trace-cmd.c',
    'trace-convert.c',
    'trace-dump.c',
    'trace-hist.c',
    'trace-list.c',
    'trace-listen.c',
    'trace-mem.c',
    'trace-profile.c',
    'trace-read.c',
    'trace-record.c',
    'trace-restore.c',
    'trace-setup-guest.c',
    'trace-show.c',
    'trace-snapshot.c',
    'trace-split.c',
    'trace-stack.c',
    'trace-stat.c',
    'trace-stream.c',
    'trace-tsync.c',
    'trace-usage.c',
    'trace-vm.c',
]

if vsock_defined
    sources += 'trace-vsock.c'
endif

trace_cmd_incdir = include_directories(['.', 'include'])

executable(
    'trace-cmd',
    sources,
    dependencies: [
        libtraceevent_dep,
        libtracefs_dep,
        zlib_dep,
        libzstd_dep,
        audit_dep],
    include_directories: [
        incdir,
        trace_cmd_incdir,
        libtracecmd_incdir,
        libtracecmd_private_incdir,
        libtracecmd_ext_incdir],
    link_with: [static_libtracecmd],
    install: true,
    install_dir: bindir)

install_data(
    'trace-cmd.bash',
    install_dir: datadir + '/bash-completion/completions')
