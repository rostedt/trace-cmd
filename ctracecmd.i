// tracecmd.i
%module ctracecmd
%include "typemaps.i"
%include "constraints.i"

%nodefaultctor record;
%nodefaultdtor record;

%apply Pointer NONNULL { struct tracecmd_input *handle };
%apply Pointer NONNULL { struct pevent *pevent };
%apply Pointer NONNULL { struct format_field * };
%apply unsigned long long *OUTPUT {unsigned long long *}
%apply int *OUTPUT {int *}


%{
#include "trace-cmd.h"
%}


%typemap(in) PyObject *pyfunc {
	if (!PyCallable_Check($input)) {
		PyErr_SetString(PyExc_TypeError, "Need a callable object!");
		return NULL;
	}
	$1 = $input;
}

%ignore python_callback;

%inline %{
static int python_callback(struct trace_seq *s,
			   struct pevent_record *record,
			   struct event_format *event,
			   void *context);

PyObject *convert_pevent(unsigned long pevent)
{
	void *pev = (void *)pevent;
	return SWIG_NewPointerObj(SWIG_as_voidptr(pev), SWIGTYPE_p_pevent, 0);
}

void py_pevent_register_event_handler(struct pevent *pevent, int id,
				      char *subsys, char *evname,
				      PyObject *pyfunc)
{
	Py_INCREF(pyfunc);
	pevent_register_event_handler(pevent, id, subsys, evname,
				      python_callback, pyfunc);
}

static PyObject *py_field_get_data(struct format_field *f, struct pevent_record *r)
{
	if (!strncmp(f->type, "__data_loc ", 11)) {
		unsigned long long val;
		int len, offset;

		if (pevent_read_number_field(f, r->data, &val)) {
			PyErr_SetString(PyExc_TypeError,
					"Field is not a valid number");
			return NULL;
		}

		/*
		 * The actual length of the dynamic array is stored
		 * in the top half of the field, and the offset
		 * is in the bottom half of the 32 bit field.
		 */
		offset = val & 0xffff;
		len = val >> 16;

		return PyBuffer_FromMemory((char *)r->data + offset, len);
	}

	return PyBuffer_FromMemory((char *)r->data + f->offset, f->size);
}

static PyObject *py_field_get_str(struct format_field *f, struct pevent_record *r)
{
	if (!strncmp(f->type, "__data_loc ", 11)) {
		unsigned long long val;
		int offset;

		if (pevent_read_number_field(f, r->data, &val)) {
			PyErr_SetString(PyExc_TypeError,
					"Field is not a valid number");
			return NULL;
		}

		/*
		 * The actual length of the dynamic array is stored
		 * in the top half of the field, and the offset
		 * is in the bottom half of the 32 bit field.
		 */
		offset = val & 0xffff;

		return PyString_FromString((char *)r->data + offset);
	}

	return PyString_FromStringAndSize((char *)r->data + f->offset,
				strnlen((char *)r->data + f->offset, f->size));
}

static PyObject *py_format_get_keys(struct event_format *ef)
{
	PyObject *list;
	struct format_field *f;

	list = PyList_New(0);

	for (f = ef->format.fields; f; f = f->next) {
		if (PyList_Append(list, PyString_FromString(f->name))) {
			Py_DECREF(list);
			return NULL;
		}
	}

	return list;
}
%}


%wrapper %{
static int python_callback(struct trace_seq *s,
			   struct pevent_record *record,
			   struct event_format *event,
			   void *context)
{
	PyObject *arglist, *result;
	int r = 0;

	record->ref_count++;

	arglist = Py_BuildValue("(OOO)",
		SWIG_NewPointerObj(SWIG_as_voidptr(s),
				   SWIGTYPE_p_trace_seq, 0),
		SWIG_NewPointerObj(SWIG_as_voidptr(record),
				   SWIGTYPE_p_pevent_record, 0),
		SWIG_NewPointerObj(SWIG_as_voidptr(event),
				   SWIGTYPE_p_event_format, 0));

	result = PyEval_CallObject(context, arglist);
	Py_XDECREF(arglist);
	if (result && result != Py_None) {
		if (!PyInt_Check(result)) {
			PyErr_SetString(PyExc_TypeError,
					"callback must return int");
			PyErr_Print();
			Py_XDECREF(result);
			return 0;
		}
		r = PyInt_AS_LONG(result);
	} else if (result == Py_None)
		r = 0;
	else
		PyErr_Print();

	Py_XDECREF(result);

	return r;
}
%}


%ignore trace_seq_vprintf;
%ignore vpr_stat;

/* SWIG can't grok these, define them to nothing */
#define __trace
#define __attribute__(x)
#define __thread

%include "trace-cmd.h"
%include "event-parse.h"
