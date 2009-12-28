// tracecmd.i
%module ctracecmd
%include typemaps.i

%{
#include "trace-cmd.h"
%}

%typemap(out) unsigned long long {
$result = PyLong_FromUnsignedLongLong((unsigned long long) $1);
}

%inline %{
PyObject *pevent_read_number_field_py(struct format_field *f, void *data)
{
        unsigned long long val;
        int ret;

        ret = pevent_read_number_field(f, data, &val);
        if (ret)
                Py_RETURN_NONE;
        else
                return PyLong_FromUnsignedLongLong(val);
}
%}


/* SWIG can't grok these, define them to nothing */
#define __trace
#define __attribute__(x)
#define __thread

%include "trace-cmd.h"
%include "parse-events.h"
