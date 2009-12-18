// tracecmd.i
%module ctracecmd
%include typemaps.i

%{
#include "trace-cmd.h"
%}

/* typemaps must come before the implementation of wrapped functions */
extern int pevent_read_number_field_32(struct format_field *f, void *data,
                                       unsigned long *OUTPUT, unsigned long *OUTPUT);

%inline %{
int pevent_read_number_field_32(struct format_field *f, void *data, unsigned long *hi, unsigned long *lo)
{
        unsigned long long val64;
        int ret;
        ret = pevent_read_number_field(f, data, &val64);
        *hi = (unsigned long)(val64>>32);
        *lo = (unsigned long)((val64<<32)>>32);
        return ret;
}
%}


/* SWIG can't grok these, define them to nothing */
#define __trace
#define __attribute__(x)
#define __thread

%include "trace-cmd.h"
%include "parse-events.h"
