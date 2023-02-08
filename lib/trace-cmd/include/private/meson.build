# SPDX-License-Identifier: LGPL-2.1
#
# Copyright (c) 2023 Daniel Wagner, SUSE LLC

config_h = configure_file(
    output: 'config.h',
    configuration: conf
)

libtracecmd_private_incdir = include_directories(['.'])

config_dep = declare_dependency(
    include_directories : libtracecmd_private_incdir,
    sources: config_h)
