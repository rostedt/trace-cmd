/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2016 Red Hat Inc, Steven Rostedt <srostedt@redhat.com>
 *
 */
#ifndef _KSHARK_PLUGIN_H
#define _KSHARK_PLUGIN_H

#define KSHARK_PLUGIN_LOADER kshark_plugin_loader
#define KSHARK_PLUGIN_UNLOADER kshark_plugin_unloader

#define _MAKE_STR(x)	#x
#define MAKE_STR(x)	_MAKE_STR(x)
#define KSHARK_PLUGIN_LOADER_NAME MAKE_STR(KSHARK_PLUGIN_LOADER)
#define KSHARK_PLUGIN_UNLOADER_NAME MAKE_STR(KSHARK_PLUGIN_UNLOADER)

typedef int (*kshark_plugin_load_func)(void *info);
typedef int (*kshark_plugin_unload_func)(void *info);


#endif
