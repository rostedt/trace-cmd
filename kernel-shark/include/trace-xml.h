/* SPDX-License-Identifier: LGPL-2.1 */
/*
 * Copyright (C) 2009, 2010 Red Hat Inc, Steven Rostedt <srostedt@redhat.com>
 *
 */
#ifndef __TRACE_XML_H
#define __TRACE_XML_H

struct tracecmd_xml_handle;
struct tacecmd_xml_system;
struct tacecmd_xml_system_node;

struct tracecmd_xml_handle *tracecmd_xml_create(const char *name, const char *version);
struct tracecmd_xml_handle *tracecmd_xml_open(const char *name);
void tracecmd_xml_close(struct tracecmd_xml_handle *handle);

int tracecmd_xml_start_system(struct tracecmd_xml_handle *handle,
			      const char *system);
void tracecmd_xml_end_system(struct tracecmd_xml_handle *handle);

int tracecmd_xml_start_sub_system(struct tracecmd_xml_handle *handle,
				  const char *subsystem);
void tracecmd_xml_end_sub_system(struct tracecmd_xml_handle *handle);

int tracecmd_xml_write_element(struct tracecmd_xml_handle *handle,
			       const char *obj,
			       const char *fmt, ...);

struct tracecmd_xml_handle *tracecmd_xml_open(const char *file);

struct tracecmd_xml_system *
tracecmd_xml_find_system(struct tracecmd_xml_handle *handle,
			 const char *system);
void tracecmd_xml_free_system(struct tracecmd_xml_system *system);
struct tracecmd_xml_system_node *
tracecmd_xml_system_node(struct tracecmd_xml_system *system);
const char *tracecmd_xml_node_type(struct tracecmd_xml_system_node *tnode);
struct tracecmd_xml_system_node *
tracecmd_xml_node_child(struct tracecmd_xml_system_node *tnode);
struct tracecmd_xml_system_node *
tracecmd_xml_node_next(struct tracecmd_xml_system_node *tnode);
const char *tracecmd_xml_node_value(struct tracecmd_xml_handle *handle,
				    struct tracecmd_xml_system_node *tnode);
int tracecmd_xml_system_exists(struct tracecmd_xml_handle *handle,
			       const char *system);

#endif /* __TRACE_XML_H */
