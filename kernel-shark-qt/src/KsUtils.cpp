// SPDX-License-Identifier: LGPL-2.1

/*
 * Copyright (C) 2017 VMware Inc, Yordan Karadzhov <ykaradzhov@vmware.com>
 */

/**
 *  @file    KsUtils.cpp
 *  @brief   KernelShark Utils.
 */

// KernelShark
#include "KsUtils.hpp"

namespace KsUtils {

/** @brief Get a sorted vector of Task's Pids. */
QVector<int> getPidList()
{
	kshark_context *kshark_ctx(nullptr);
	int nTasks, *tempPids;
	QVector<int> pids;

	if (!kshark_instance(&kshark_ctx))
		return pids;

	nTasks = kshark_get_task_pids(kshark_ctx, &tempPids);
	for (int r = 0; r < nTasks; ++r) {
		pids.append(tempPids[r]);
	}

	free(tempPids);

	qSort(pids);

	return pids;
}

/**
 * Set the bit of the filter mask of the kshark session context responsible
 * for the visibility of the events in the Table View.
 */
void listFilterSync(bool state)
{
	kshark_context *kshark_ctx(nullptr);

	if (!kshark_instance(&kshark_ctx))
		return;

	if (state) {
		kshark_ctx->filter_mask |= KS_TEXT_VIEW_FILTER_MASK;
	} else {
		kshark_ctx->filter_mask &= ~KS_TEXT_VIEW_FILTER_MASK;
	}
}

/**
 * Set the bit of the filter mask of the kshark session context responsible
 * for the visibility of the events in the Graph View.
 */
void graphFilterSync(bool state)
{
	kshark_context *kshark_ctx(nullptr);

	if (!kshark_instance(&kshark_ctx))
		return;

	if (state) {
		kshark_ctx->filter_mask |= KS_GRAPH_VIEW_FILTER_MASK;
	} else {
		kshark_ctx->filter_mask &= ~KS_GRAPH_VIEW_FILTER_MASK;
	}
}

/**
 * @brief Simple CPU matching function to be user for data collections.
 *
 * @param kshark_ctx: Input location for the session context pointer.
 * @param e: kshark_entry to be checked.
 * @param cpu: Matching condition value.
 *
 * @returns True if the CPU of the entry matches the value of "cpu" and
 * 	    the entry is visibility in Graph. Otherwise false.
 */
bool matchCPUVisible(struct kshark_context *kshark_ctx,
		     struct kshark_entry *e, int cpu)
{
	return (e->cpu == cpu && (e->visible & KS_GRAPH_VIEW_FILTER_MASK));
}

}; // KsUtils

/** A stream operator for converting QColor into KsPlot::Color. */
KsPlot::Color& operator <<(KsPlot::Color &thisColor, const QColor &c)
{
	thisColor.set(c.red(), c.green(), c.blue());

	return thisColor;
}

/** Create a default (empty) KsDataStore. */
KsDataStore::KsDataStore(QWidget *parent)
: QObject(parent),
  _tep(nullptr),
  _rows(nullptr),
  _dataSize(0)
{}

/** Destroy the KsDataStore object. */
KsDataStore::~KsDataStore()
{}

/** Load trace data for file. */
void KsDataStore::loadDataFile(const QString &file)
{
	kshark_context *kshark_ctx(nullptr);

	if (!kshark_instance(&kshark_ctx))
		return;

	clear();

	if (!kshark_open(kshark_ctx, file.toStdString().c_str())) {
		qCritical() << "ERROR Loading file " << file;
		return;
	}

	_tep = kshark_ctx->pevent;

	if (kshark_ctx->event_handlers == nullptr)
		kshark_handle_plugins(kshark_ctx, KSHARK_PLUGIN_INIT);
	else
		kshark_handle_plugins(kshark_ctx, KSHARK_PLUGIN_UPDATE);

	_dataSize = kshark_load_data_entries(kshark_ctx, &_rows);
}

void KsDataStore::_freeData()
{
	if (_dataSize) {
		for (size_t r = 0; r < _dataSize; ++r)
			free(_rows[r]);

		free(_rows);
		_rows = nullptr;
	}

	_dataSize = 0;
}

/** Reload the trace data. */
void KsDataStore::reload()
{
	kshark_context *kshark_ctx(nullptr);

	if (!kshark_instance(&kshark_ctx))
		return;

	_freeData();

	_dataSize = kshark_load_data_entries(kshark_ctx, &_rows);
	_tep = kshark_ctx->pevent;

	emit updateWidgets(this);
}

/** Free the loaded trace data and close the file. */
void KsDataStore::clear()
{
	kshark_context *kshark_ctx(nullptr);

	_freeData();
	_tep = nullptr;

	if (kshark_instance(&kshark_ctx) && kshark_ctx->handle)
		kshark_close(kshark_ctx);
}

/** Update the visibility of the entries (filter). */
void KsDataStore::update()
{
	kshark_context *kshark_ctx(nullptr);

	if (!kshark_instance(&kshark_ctx))
		return;

	if (kshark_filter_is_set(kshark_ctx)) {
		kshark_filter_entries(kshark_ctx, _rows, _dataSize);
		emit updateWidgets(this);
	}
}

/** Register a collection of visible entries for each CPU. */
void KsDataStore::registerCPUCollections()
{
	kshark_context *kshark_ctx(nullptr);

	if (!kshark_instance(&kshark_ctx) ||
	    !kshark_filter_is_set(kshark_ctx))
		return;

	int nCPUs = tep_get_cpus(_tep);
	for (int cpu = 0; cpu < nCPUs; ++cpu) {
		kshark_register_data_collection(kshark_ctx,
						_rows, _dataSize,
						KsUtils::matchCPUVisible,
						cpu,
						0);
	}
}

void KsDataStore::_unregisterCPUCollections()
{
	kshark_context *kshark_ctx(nullptr);

	if (!kshark_instance(&kshark_ctx))
		return;

	int nCPUs = tep_get_cpus(_tep);
	for (int cpu = 0; cpu < nCPUs; ++cpu) {
		kshark_unregister_data_collection(&kshark_ctx->collections,
						  KsUtils::matchCPUVisible,
						  cpu);
	}
}

void KsDataStore::_applyIdFilter(int filterId, QVector<int> vec)
{
	kshark_context *kshark_ctx(nullptr);

	if (!kshark_instance(&kshark_ctx))
		return;

	switch (filterId) {
		case KS_SHOW_EVENT_FILTER:
		case KS_HIDE_EVENT_FILTER:
			kshark_filter_clear(kshark_ctx, KS_SHOW_EVENT_FILTER);
			kshark_filter_clear(kshark_ctx, KS_HIDE_EVENT_FILTER);
			break;
		case KS_SHOW_TASK_FILTER:
		case KS_HIDE_TASK_FILTER:
			kshark_filter_clear(kshark_ctx, KS_SHOW_TASK_FILTER);
			kshark_filter_clear(kshark_ctx, KS_HIDE_TASK_FILTER);
			break;
		default:
			return;
	}

	for (auto &&pid: vec)
		kshark_filter_add_id(kshark_ctx, filterId, pid);

	if (!_tep)
		return;

	_unregisterCPUCollections();

	/*
	 * If the advanced event filter is set, the data has to be reloaded,
	 * because the advanced filter uses tep_records.
	 */
	if (kshark_ctx->advanced_event_filter->filters)
		reload();
	else
		kshark_filter_entries(kshark_ctx, _rows, _dataSize);

	registerCPUCollections();

	emit updateWidgets(this);
}

/** Apply Show Task filter. */
void KsDataStore::applyPosTaskFilter(QVector<int> vec)
{
	_applyIdFilter(KS_SHOW_TASK_FILTER, vec);
}

/** Apply Hide Task filter. */
void KsDataStore::applyNegTaskFilter(QVector<int> vec)
{
	_applyIdFilter(KS_HIDE_TASK_FILTER, vec);
}

/** Apply Show Event filter. */
void KsDataStore::applyPosEventFilter(QVector<int> vec)
{
	_applyIdFilter(KS_SHOW_EVENT_FILTER, vec);
}

/** Apply Hide Event filter. */
void KsDataStore::applyNegEventFilter(QVector<int> vec)
{
	_applyIdFilter(KS_HIDE_EVENT_FILTER, vec);
}

/** Disable all filters. */
void KsDataStore::clearAllFilters()
{
	kshark_context *kshark_ctx(nullptr);

	if (!kshark_instance(&kshark_ctx) || !_tep)
		return;

	_unregisterCPUCollections();

	kshark_filter_clear(kshark_ctx, KS_SHOW_TASK_FILTER);
	kshark_filter_clear(kshark_ctx, KS_HIDE_TASK_FILTER);
	kshark_filter_clear(kshark_ctx, KS_SHOW_EVENT_FILTER);
	kshark_filter_clear(kshark_ctx, KS_HIDE_EVENT_FILTER);

	tep_filter_reset(kshark_ctx->advanced_event_filter);
	kshark_clear_all_filters(kshark_ctx, _rows, _dataSize);

	emit updateWidgets(this);
}

/**
 * @brief Create Plugin Manager. Use list of plugins declared in the
 *	  CMake-generated header file.
 */
KsPluginManager::KsPluginManager(QWidget *parent)
: QObject(parent)
{
	kshark_context *kshark_ctx(nullptr);
	_parsePluginList();

	if (!kshark_instance(&kshark_ctx))
		return;

	registerFromList(kshark_ctx);
}

/** Parse the plugin list declared in the CMake-generated header file. */
void KsPluginManager::_parsePluginList()
{
	_ksPluginList = KsUtils::getPluginList();
	int nPlugins = _ksPluginList.count();

	_registeredKsPlugins.resize(nPlugins);
	for (int i = 0; i < nPlugins; ++i) {
		if (_ksPluginList[i].contains(" default", Qt::CaseInsensitive)) {
			_ksPluginList[i].remove(" default", Qt::CaseInsensitive);
			_registeredKsPlugins[i] = true;
		} else {
			_registeredKsPlugins[i] = false;
		}
	}
}

/**
 * Register the plugins by using the information in "_ksPluginList" and
 * "_registeredKsPlugins".
 */
void KsPluginManager::registerFromList(kshark_context *kshark_ctx)
{
	auto lamRegBuiltIn = [&kshark_ctx](const QString &plugin)
	{
		char *lib;
		int n;

		n = asprintf(&lib, "%s/lib/plugin-%s.so",
			     KS_DIR, plugin.toStdString().c_str());
		if (n <= 0)
			return;

		kshark_register_plugin(kshark_ctx, lib);
		free(lib);
	};

	auto lamRegUser = [&kshark_ctx](const QString &plugin)
	{
		const char *lib = plugin.toStdString().c_str();
		kshark_register_plugin(kshark_ctx, lib);
	};

	_forEachInList(_ksPluginList,
		       _registeredKsPlugins,
		       lamRegBuiltIn);

	_forEachInList(_userPluginList,
		       _registeredUserPlugins,
		       lamRegUser);
}

/**
 * Unegister the plugins by using the information in "_ksPluginList" and
 * "_registeredKsPlugins".
 */
void KsPluginManager::unregisterFromList(kshark_context *kshark_ctx)
{
	auto lamUregBuiltIn = [&kshark_ctx](const QString &plugin)
	{
		char *lib;
		int n;

		n = asprintf(&lib, "%s/lib/plugin-%s.so",
			     KS_DIR, plugin.toStdString().c_str());
		if (n <= 0)
			return;

		kshark_unregister_plugin(kshark_ctx, lib);
		free(lib);
	};

	auto lamUregUser = [&kshark_ctx](const QString &plugin)
	{
		const char *lib = plugin.toStdString().c_str();
		kshark_unregister_plugin(kshark_ctx, lib);
	};

	_forEachInList(_ksPluginList,
		       _registeredKsPlugins,
			lamUregBuiltIn);

	_forEachInList(_userPluginList,
		       _registeredUserPlugins,
			lamUregUser);
}

/**
 * @brief Register a Plugin.
 *
 * @param plugin: provide here the name of the plugin (as in the CMake-generated
 *		  header file) of a name of the plugin's library file (.so).
 */
void KsPluginManager::registerPlugin(const QString &plugin)
{
	kshark_context *kshark_ctx(nullptr);
	char *lib;
	int n;

	if (!kshark_instance(&kshark_ctx))
		return;

	for (int i = 0; i < _ksPluginList.count(); ++i) {
		if (_ksPluginList[i] == plugin) {
			/*
			 * The argument is the name of the plugin. From the
			 * name get the library .so file.
			 */
			n = asprintf(&lib, "%s/lib/plugin-%s.so",
					KS_DIR, plugin.toStdString().c_str());
			if (n > 0) {
				kshark_register_plugin(kshark_ctx, lib);
				_registeredKsPlugins[i] = true;
				free(lib);
			}

			return;

		} else if (plugin.contains("/lib/plugin-" + _ksPluginList[i],
					   Qt::CaseInsensitive)) {
			/*
			 * The argument is the name of the library .so file.
			 */
			n = asprintf(&lib, "%s", plugin.toStdString().c_str());
			if (n > 0) {
				kshark_register_plugin(kshark_ctx, lib);
				_registeredKsPlugins[i] = true;
				free(lib);
			}

			return;
		}
	}

	/* No plugin with this name in the list. Try to add it anyway. */
	if (plugin.endsWith(".so") && QFileInfo::exists(plugin)) {
		kshark_register_plugin(kshark_ctx,
				       plugin.toStdString().c_str());

		_userPluginList.append(plugin);
		_registeredUserPlugins.append(true);
	} else {
		qCritical() << "ERROR: " << plugin << "cannot be registered!";
	}
}

/** @brief Unregister a Built in KernelShark plugin.
 *<br>
 * WARNING: Do not use this function to unregister User plugins.
 * Instead use directly kshark_unregister_plugin().
 *
 * @param plugin: provide here the name of the plugin (as in the CMake-generated
 *		  header file) or a name of the plugin's library file (.so).
 *
 */
void KsPluginManager::unregisterPlugin(const QString &plugin)
{
	kshark_context *kshark_ctx(nullptr);
	char *lib;
	int n;

	if (!kshark_instance(&kshark_ctx))
		return;

	for (int i = 0; i < _ksPluginList.count(); ++i) {
		if (_ksPluginList[i] == plugin) {
			/*
			 * The argument is the name of the plugin. From the
			 * name get the library .so file.
			 */
			n = asprintf(&lib, "%s/lib/plugin-%s.so", KS_DIR,
				     plugin.toStdString().c_str());
			if (n > 0) {
				kshark_unregister_plugin(kshark_ctx, lib);
				_registeredKsPlugins[i] = false;
				free(lib);
			}

			return;
		} else if  (plugin.contains("/lib/plugin-" +
			                   _ksPluginList[i], Qt::CaseInsensitive)) {
			/*
			 * The argument is the name of the library .so file.
			 */
			n = asprintf(&lib, "%s", plugin.toStdString().c_str());
			if (n > 0) {
				kshark_unregister_plugin(kshark_ctx, lib);
				_registeredKsPlugins[i] = false;
				free(lib);
			}

			return;
		}
	}
}

/** Unload all plugins. */
void KsPluginManager::unloadAll()
{
	kshark_context *kshark_ctx(nullptr);

	if (!kshark_instance(&kshark_ctx))
		return;

	kshark_handle_plugins(kshark_ctx, KSHARK_PLUGIN_CLOSE);
	kshark_free_plugin_list(kshark_ctx->plugins);
	kshark_ctx->plugins = nullptr;
	kshark_free_event_handler_list(kshark_ctx->event_handlers);

	unregisterFromList(kshark_ctx);
}

/** @brief Update (change) the Plugins.
 *
 * @param pluginIds: The indexes of the plugins to be loaded.
 */
void KsPluginManager::updatePlugins(QVector<int> pluginIds)
{
	kshark_context *kshark_ctx(nullptr);

	if (!kshark_instance(&kshark_ctx))
		return;

	auto register_plugins = [&] (QVector<int> ids)
	{
		int nKsPlugins = _registeredKsPlugins.count();

		/* First clear all registered plugins. */
		for (auto &p: _registeredKsPlugins)
			p = false;
		for (auto &p: _registeredUserPlugins)
			p = false;

		/* The vector contains the indexes of those to register. */
		for (auto const &p: ids) {
			if (p < nKsPlugins)
				_registeredKsPlugins[p] = true;
			else
				_registeredUserPlugins[p - nKsPlugins] = true;
		}
		registerFromList(kshark_ctx);
	};

	if (!kshark_ctx->pevent) {
		kshark_free_plugin_list(kshark_ctx->plugins);
		kshark_ctx->plugins = nullptr;

		/*
		 * No data is loaded. For the moment, just register the
		 * plugins. Handling of the plugins will be done after
		 * we load a data file.
		 */
		register_plugins(pluginIds);
		return;
	}

	/* Clean up all old plugins first. */
	unloadAll();

	/* Now load. */
	register_plugins(pluginIds);
	kshark_handle_plugins(kshark_ctx, KSHARK_PLUGIN_INIT);

	emit dataReload();
}
