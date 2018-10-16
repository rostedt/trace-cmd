/* SPDX-License-Identifier: LGPL-2.1 */

/*
 * Copyright (C) 2017 VMware Inc, Yordan Karadzhov <ykaradzhov@vmware.com>
 */

/**
 *  @file    KsMainWindow.hpp
 *  @brief   KernelShark GUI main window.
 */

#ifndef _KS_MAINWINDOW_H
#define _KS_MAINWINDOW_H

// Qt
#include <QMainWindow>
#include <QLocalServer>

// KernelShark
#include "KsTraceViewer.hpp"
#include "KsTraceGraph.hpp"
#include "KsSession.hpp"
#include "KsUtils.hpp"

/**
 * The KsMainWindow class provides Main window for the KernelShark GUI.
 */
class KsMainWindow : public QMainWindow
{
	Q_OBJECT
public:
	explicit KsMainWindow(QWidget *parent = nullptr);

	~KsMainWindow();

	void loadDataFile(const QString &fileName);

	void loadSession(const QString &fileName);

	/**
	 * @brief
	 *
	 * @param plugin: can be the name of the plugin or the plugin's library
	 * file (including absolute or relative path).
	 */
	void registerPlugin(const QString &plugin)
	{
		_plugins.registerPlugin(plugin);
	}

	/**
	 * @brief
	 *
	 * @param plugin: can be the name of the plugin or the plugin's library
	 * file (including absolute path).
	 */
	void unregisterPlugin(const QString &plugin)
	{
		_plugins.unregisterPlugin(plugin);
	}

	void resizeEvent(QResizeEvent* event);

private:
	QSplitter	_splitter;

	/** GUI session. */
	KsSession	_session;

	/** Data Manager. */
	KsDataStore	_data;

	/** Widget for reading and searching in the trace data. */
	KsTraceViewer	_view;

	/** Widget for graphical visualization of the trace data. */
	KsTraceGraph	_graph;

	/** Dual Marker State Machine. */
	KsDualMarkerSM	_mState;

	/** Plugin manager. */
	KsPluginManager	_plugins;

	/** The process used to record trace data. */
	QProcess	_capture;

	/** Local Server used for comunucation with the Capture process. */
	QLocalServer	_captureLocalServer;

	// File menu.
	QAction		_openAction;

	QAction		_restorSessionAction;

	QAction		_importSessionAction;

	QAction		_exportSessionAction;

	QAction		_quitAction;

	// Filter menu.
	QAction		_importFilterAction;

	QAction		_exportFilterAction;

	QWidgetAction	_graphFilterSyncAction;

	QWidgetAction	_listFilterSyncAction;

	QAction		_showEventsAction;

	QAction		_showTasksAction;

	QAction		_hideTasksAction;

	QAction		_advanceFilterAction;

	QAction		_clearAllFilters;

	// Plots menu.
	QAction		_cpuSelectAction;

	QAction		_taskSelectAction;

	// Tools menu.
	QAction		_pluginsAction;

	QAction		_captureAction;

	QWidgetAction	_colorAction;

	QWidget		_colSlider;

	QSlider		_colorPhaseSlider;

	QAction		_fullScreenModeAction;

	bool		_isFullScreen;

	// Help menu.
	QAction		_aboutAction;

	QAction		_contentsAction;

	void _open();

	void _restorSession();

	void _importSession();

	void _exportSession();

	void _importFilter();

	void _exportFilter();

	void _listFilterSync(int state);

	void _graphFilterSync(int state);

	void _showEvents();

	void _showTasks();

	void _hideTasks();

	void _advancedFiltering();

	void _clearFilters();

	void _cpuSelect();

	void _taskSelect();

	void _pluginSelect();

	void _record();

	void _setColorPhase(int);

	void _fullScreenMode();

	void _aboutInfo();

	void _contents();

	void _captureStarted();

	void _captureError(QProcess::ProcessError error);

	void _readSocket();

	void _splitterMoved(int pos, int index);

	void _createActions();

	void _createMenus();

	void _initCapture();

	void _updateSession();

	inline void _resizeEmpty() {resize(SCREEN_WIDTH * .5, FONT_HEIGHT * 3);}

	void _error(const QString &text, const QString &errCode,
		    bool resize, bool unloadPlugins);

private slots:
	void _captureFinished(int, QProcess::ExitStatus);
};

#endif // _KS_MAINWINDOW_H
