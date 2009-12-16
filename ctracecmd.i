// tracecmd.i
%module ctracecmd

%{
#include "trace-cmd.h"
%}

%inline %{
%}

/* SWIG can't grok these, define them to nothing */
#define __trace
#define __attribute__(x)
#define __thread

%include "trace-cmd.h"
%include "parse-events.h"
