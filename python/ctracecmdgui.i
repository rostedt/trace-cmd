// ctracecmdgui.i
%module ctracecmdgui
%include typemaps.i

%{
#include "trace-view-store.h"
#include <pygobject.h>
#include <pyglib.h>
#include <Python.h>

extern GtkTreeModel *trace_view_store_as_gtk_tree_model(struct trace_view_store *store);

PyObject *
pytype_from_gtype(GType gtype)
{
    PyTypeObject *pt = NULL;
    switch (gtype) {
    case G_TYPE_INT:
    case G_TYPE_UINT:
        pt = &PyLong_Type;
        break;
    case G_TYPE_STRING:
        pt = &PyUnicode_Type;
        break;
    default:
        return Py_None;
    }
    return (PyObject *)pt;
}
%}


/* return python longs from unsigned long long functions */
%typemap(out) unsigned long long {
    $result = PyLong_FromUnsignedLongLong((unsigned long long) $1);
}

/* help swig cope with g* types */
%typemap(in) gint {
    $1 = PyInt_AsLong($input);
}
%typemap(out) gint {
    $result = PyInt_FromLong($1);
}
%typemap(in) guint {
    $1 = PyLong_AsUnsignedLong($input);
}
%typemap(out) guint {
    $result = PyLong_FromUnsignedLong($1);
}
%typemap(in) guint64 {
    $1 = PyLong_AsUnsignedLongLong($input);
}
%typemap(out) guint64 {
    $result = PyLong_FromUnsignedLongLong($1);
}
%typemap(out) GType {
    $result = pytype_from_gtype($1);
}
%typemap(out) GtkTreeModelFlags {
    $result = PyLong_FromLong($1);
}


%inline %{
GtkTreeModel *trace_view_store_as_gtk_tree_model(struct trace_view_store *store)
{
    return GTK_TREE_MODEL(store);
}
%}


/* SWIG can't grok these, define them to nothing */
#define __trace
#define __attribute__(x)
#define __thread

%include "trace-view-store.h"
