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
 * License along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 *
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>

#include <libxml/xmlwriter.h>
#include <libxml/parser.h>
#include <libxml/encoding.h>

#include "trace-cmd.h"
#include "trace-xml.h"

struct tracecmd_xml_handle {
	xmlTextWriterPtr	writer;
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

struct tracecmd_xml_handle *tracecmd_xml_create(const char *name)
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

	return handle;

 fail_close:
	xmlFreeTextWriter(handle->writer);
 fail_free:
	free(handle);
	return NULL;
}

int tracecmd_xml_start_system(struct tracecmd_xml_handle *handle,
			      const char *system, const char *version)
{
	int ret;

	ret = xmlTextWriterStartElement(handle->writer,
					BAD_CAST system);

	if (ret < 0)
		return ret;

	ret = tracecmd_xml_write_element(handle, "Version", "%s", version);
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
		xmlTextWriterEndDocument(handle->writer);
		xmlFreeTextWriter(handle->writer);
	}

	free(handle);
}
