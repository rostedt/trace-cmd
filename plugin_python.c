#include <Python.h>
#include <stdio.h>
#include "trace-cmd.h"

#ifndef PYTHON_DIR
#define PYTHON_DIR "."
#endif

static const char pypath[] =
"import sys\n"
"sys.path.append(\"" PYTHON_DIR "\")\n";

static const char pyload[] =
"import imp, tracecmd, ctracecmd\n"
"fn = r'%s'\n"
"file = open(fn, 'r')\n"
"try:\n"
"   module = imp.load_source('%s', fn, file)\n"
"   module.register(tracecmd.PEvent(ctracecmd.convert_pevent(pevent)))\n"
"finally:\n"
"   file.close()\n";

static void load_plugin(struct pevent *pevent, const char *path,
			const char *name, void *data)
{
	PyObject *globals = data;
	int len = strlen(path) + strlen(name) + 2;
	int nlen = strlen(name) + 1;
	char *full = malloc(len);
	char *n = malloc(nlen);
	char *load;
	PyObject *res;

	if (!full || !n)
		return;

	strcpy(full, path);
	strcat(full, "/");
	strcat(full, name);

	strcpy(n, name);
	n[nlen - 4] = '\0';

	asprintf(&load, pyload, full, n);
	if (!load)
		return;

	res = PyRun_String(load, Py_file_input, globals, globals);
	if (!res) {
		fprintf(stderr, "failed loading %s\n", full);
		PyErr_Print();
	} else
		Py_DECREF(res);

	free(load);
}

int PEVENT_PLUGIN_LOADER(struct pevent *pevent)
{
	PyObject *globals, *m, *py_pevent, *str, *res;
	char **plugin_list;

	/* Only load plugins if they exist */
	plugin_list = trace_util_find_plugin_files(".py");
	if (!plugin_list)
		return 0;
	trace_util_free_plugin_files(plugin_list);

	Py_Initialize();

	m = PyImport_AddModule("__main__");
	globals = PyModule_GetDict(m);

	res = PyRun_String(pypath, Py_file_input, globals, globals);
	if (!res) {
		PyErr_Print();
		return -1;
	} else
		Py_DECREF(res);

	str = PyString_FromString("pevent");
	if (!str)
		return -ENOMEM;

	py_pevent = PyLong_FromUnsignedLong((unsigned long)pevent);
	if (!py_pevent)
		return -ENOMEM;

	if (PyDict_SetItem(globals, str, py_pevent))
		fprintf(stderr, "failed to insert pevent\n");

	Py_DECREF(py_pevent);
	Py_DECREF(str);

	trace_util_load_plugins(pevent, ".py", load_plugin, globals);

	return 0;
}

int PEVENT_PLUGIN_UNLOADER(void)
{
	Py_Finalize();
	return 0;
}
