/*
 * Copyright (C) 2009, 2010 Red Hat Inc, Steven Rostedt <srostedt@redhat.com>
 *
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation;
 * version 2.1 of the License (not later!)
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program; if not,  see <http://www.gnu.org/licenses>
 *
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>

#include <libxml/xmlwriter.h>
#include <libxml/parser.h>
#include <libxml/xpath.h>

#include "trace-cmd.h"
#include "trace-xml.h"

struct tracecmd_xml_handle {
	xmlTextWriterPtr	writer;
	xmlDocPtr		doc;
};

struct tracecmd_xml_system {
	struct tracecmd_xml_handle *handle;
	xmlXPathObjectPtr	result;
	xmlNodePtr		cur;
};

#define TRACE_ENCODING "UTF-8"

int tracecmd_xml_write_element(struct tracecmd_xml_handle *handle,
			       const char *obj,
			       const char *fmt, ...)
{
	va_list ap;
	int ret;

	va_start(ap, fmt);
	ret = xmlTextWriterWriteVFormatElement(handle->writer,
					       BAD_CAST obj, fmt, ap);
	va_end(ap);

	return ret;
}

struct tracecmd_xml_handle *tracecmd_xml_create(const char *name,
						const char *version)
{
	struct tracecmd_xml_handle *handle;
	int ret;

	handle = malloc_or_die(sizeof(*handle));
	memset(handle, 0, sizeof(*handle));

	handle->writer = xmlNewTextWriterFilename(name, 0);
	if (!handle->writer)
		goto fail_free;

	ret = xmlTextWriterStartDocument(handle->writer, NULL,
					 TRACE_ENCODING, NULL);
	if (ret < 0)
		goto fail_close;

	ret = xmlTextWriterStartElement(handle->writer,
					BAD_CAST "KernelShark");
	if (ret < 0)
		goto fail_close;

	return handle;

 fail_close:
	xmlFreeTextWriter(handle->writer);
 fail_free:
	free(handle);
	return NULL;
}

int tracecmd_xml_start_system(struct tracecmd_xml_handle *handle,
			      const char *system)
{
	int ret;

	ret = xmlTextWriterStartElement(handle->writer,
					BAD_CAST system);

	if (ret < 0)
		return ret;

	return 0;
}

int tracecmd_xml_start_sub_system(struct tracecmd_xml_handle *handle,
				  const char *subsystem)
{
	int ret;

	ret = xmlTextWriterStartElement(handle->writer,
					BAD_CAST subsystem);

	return ret;
}

void tracecmd_xml_end_system(struct tracecmd_xml_handle *handle)
{
	xmlTextWriterEndElement(handle->writer);
}

void tracecmd_xml_end_sub_system(struct tracecmd_xml_handle *handle)
{
	xmlTextWriterEndElement(handle->writer);
}

void tracecmd_xml_close(struct tracecmd_xml_handle *handle)
{
	if (handle->writer) {
		xmlTextWriterEndElement(handle->writer);
		xmlTextWriterEndDocument(handle->writer);
		xmlFreeTextWriter(handle->writer);
	}
	if (handle->doc) {
		xmlFreeDoc(handle->doc);
	}
	free(handle);
}

/***********************************************************/
/***  Reading XML files                                  ***/
/***********************************************************/


struct tracecmd_xml_handle *tracecmd_xml_open(const char *file)
{
	struct tracecmd_xml_handle *handle;

	handle = malloc_or_die(sizeof(*handle));
	memset(handle, 0, sizeof(*handle));

	handle->doc = xmlParseFile(file);
	if (!handle->doc)
		goto fail_free;

	return handle;

 fail_free:
	free(handle);
	return NULL;
}

struct tracecmd_xml_system *
tracecmd_xml_find_system(struct tracecmd_xml_handle *handle,
			 const char *system)
{
	struct tracecmd_xml_system *sys;
	xmlXPathContextPtr context;
	xmlXPathObjectPtr result;
	xmlChar *xpath;
	char *path;

	path = malloc_or_die(strlen(system) + 3);
	sprintf(path, "//%s", system);
	xpath = BAD_CAST path;

	context = xmlXPathNewContext(handle->doc);
	result = xmlXPathEvalExpression(xpath, context);
	free(path);

	if (xmlXPathNodeSetIsEmpty(result->nodesetval)) {
		xmlXPathFreeObject(result);
		return NULL;
	}

	sys = malloc_or_die(sizeof(*sys));
	sys->handle = handle;
	sys->result = result;
	sys->cur = result->nodesetval->nodeTab[0]->xmlChildrenNode;

	return sys;
}

struct tracecmd_xml_system_node *
tracecmd_xml_system_node(struct tracecmd_xml_system *system)
{
	return (struct tracecmd_xml_system_node *)system->cur;
}

const char *tracecmd_xml_node_type(struct tracecmd_xml_system_node *tnode)
{
	xmlNodePtr node = (xmlNodePtr)tnode;
	return (const char *)node->name;
}

struct tracecmd_xml_system_node *
tracecmd_xml_node_child(struct tracecmd_xml_system_node *tnode)
{
	xmlNodePtr node = (xmlNodePtr)tnode;
	return (struct tracecmd_xml_system_node *)node->xmlChildrenNode;
}

struct tracecmd_xml_system_node *
tracecmd_xml_node_next(struct tracecmd_xml_system_node *tnode)
{
	xmlNodePtr node = (xmlNodePtr)tnode;
	return (struct tracecmd_xml_system_node *)node->next;
}

const char *tracecmd_xml_node_value(struct tracecmd_xml_handle *handle,
				    struct tracecmd_xml_system_node *tnode)
{
	xmlNodePtr node = (xmlNodePtr)tnode;
	return (const char *)xmlNodeListGetString(handle->doc, node->xmlChildrenNode, 1);
}

void tracecmd_xml_free_system(struct tracecmd_xml_system *system)
{
	xmlXPathFreeObject(system->result);
	free(system);
}

int tracecmd_xml_system_exists(struct tracecmd_xml_handle *handle,
			       const char *system)
{
	struct tracecmd_xml_system *sys;
	int exists = 0;

	sys = tracecmd_xml_find_system(handle, system);
	if (sys) {
		exists = 1;
		tracecmd_xml_free_system(sys);
	}

	return exists;
}

