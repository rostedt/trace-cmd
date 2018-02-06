/*
 * Copyright (C) 2016 Red Hat Inc, Steven Rostedt <srostedt@redhat.com>
 *
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 2 of the License (not later!)
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not,  see <http://www.gnu.org/licenses>
 *
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
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
