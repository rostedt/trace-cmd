// tracecmd.i
%module ctracecmd
%include "typemaps.i"
%include "constraints.i"

%apply Pointer NONNULL { struct tracecmd_input *handle };
%apply Pointer NONNULL { struct pevent *pevent };
%apply unsigned long long *OUTPUT {unsigned long long *}
%apply int *OUTPUT {int *}


%{
#include "trace-cmd.h"
%}

%ignore trace_seq_vprintf;

/* SWIG can't grok these, define them to nothing */
#define __trace
#define __attribute__(x)
#define __thread

%include "trace-cmd.h"
%include "parse-events.h"
