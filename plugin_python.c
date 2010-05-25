#include <Python.h>
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdio.h>
#include <dirent.h>
#include <fnmatch.h>
#include "trace-cmd.h"

static const char pyload[] =
"import imp, tracecmd, ctracecmd\n"
"fn = r'%s'\n"
"file = open(fn, 'r')\n"
"try:\n"
"   module = imp.load_source('%s', fn, file)\n"
"   module.register(tracecmd.PEvent(ctracecmd.convert_pevent(pevent)))\n"
"finally:\n"
"   file.close()\n";

static void load_plugin(PyObject *globals, char *path, const char *name)
{
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

static int load_plugins(PyObject *globals, char *path)
{
	struct dirent *dent;
	struct stat st;
	DIR *dir;
	int ret;

	ret = stat(path, &st);
	if (ret < 0)
		return -1;

	if (!S_ISDIR(st.st_mode))
		return -1;

	dir = opendir(path);
	if (!dir)
		return -1;

	while ((dent = readdir(dir))) {
		const char *name = dent->d_name;

		if (fnmatch("*.py", name, FNM_PERIOD))
			continue;

		load_plugin(globals, path, name);
	}

	closedir(dir);

	return 0;
}

#define LOCAL_PLUGIN_DIR	".trace-cmd/python"

int PEVENT_PLUGIN_LOADER(struct pevent *pevent)
{
	char *home;
	char *path;
	int ret;
	PyObject *globals, *m, *py_pevent, *str;

	home = getenv("HOME");
	if (!home)
		return 0;

	Py_Initialize();

	m = PyImport_AddModule("__main__");
	globals = PyModule_GetDict(m);

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

	path = malloc(strlen(home) + strlen(LOCAL_PLUGIN_DIR) + 2);
	if (!path)
		return -1;

	strcpy(path, home);
	strcat(path, "/");
	strcat(path, LOCAL_PLUGIN_DIR);

	ret = load_plugins(globals, path);

	free(path);

	return ret;
}

int PEVENT_PLUGIN_UNLOADER(void)
{
	Py_Finalize();
	return 0;
}
