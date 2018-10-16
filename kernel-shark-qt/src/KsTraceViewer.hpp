/* SPDX-License-Identifier: LGPL-2.1 */

/*
 * Copyright (C) 2017 VMware Inc, Yordan Karadzhov <ykaradzhov@vmware.com>
 */

/**
 *  @file    KsTraceViewer.hpp
 *  @brief   KernelShark Trace Viewer widget.
 */

#ifndef _KS_TRACEVIEW_H
#define _KS_TRACEVIEW_H

// Qt
#include <QTableView>

// KernelShark
#include "KsUtils.hpp"
#include "KsModels.hpp"
#include "KsDualMarker.hpp"

/** Matching condition function type. To be user for searchong. */
typedef bool (*condition_func)(QString, QString);

/**
 * The KsTraceViewer class provides a widget for browsing in the trace data
 * shown in a text form.
 */
class KsTraceViewer : public QWidget
{
	Q_OBJECT
public:
	explicit KsTraceViewer(QWidget *parent = nullptr);

	void loadData(KsDataStore *data);

	void setMarkerSM(KsDualMarkerSM *m);

	void reset();

	size_t getTopRow() const;

	void setTopRow(size_t r);

	void resizeEvent(QResizeEvent* event) override;

	void keyReleaseEvent(QKeyEvent *event);

	void markSwitch();

	void showRow(size_t r, bool mark);

	void deselect();

	void update(KsDataStore *data);

signals:
	/** Signal emitted when new row is selected. */
	void select(size_t);

	/**
	 * This signal is used to re-emitted the plotTask signal of the
	 * KsQuickEntryMenu.
	 */
	void plotTask(int pid);

private:
	QVBoxLayout	_layout;

	QTableView	_view;

	KsViewModel		_model;

	KsFilterProxyModel	_proxyModel;

	QStringList	_tableHeader;

	QToolBar	_toolbar;

	QLabel		_labelSearch, _labelGrFollows;

	QComboBox	_columnComboBox;

	QComboBox	_selectComboBox;

	QLineEdit	_searchLineEdit;

	QPushButton	_prevButton, _nextButton, _searchStopButton;

	QAction		*_pbAction, *_searchStopAction;

	QCheckBox	_graphFollowsCheckBox;

	QProgressBar	_searchProgBar;

	QLabel		_searchCountLabel;

	bool		_searchDone;

	bool		_graphFollows;

	QList<int>		_matchList;

	QList<int>::iterator	_it;

	KsDualMarkerSM		*_mState;

	KsDataStore		*_data;

	enum Condition
	{
		Containes = 0,
		Match = 1,
		NotHave = 2
	};

	void _searchReset();

	void _resizeToContents();

	size_t _searchItems(int column, const QString &searchText,
			    condition_func cond);

	void _searchItemsMapReduce(int column, const QString &searchText,
				   condition_func cond);

	void _searchEditText(const QString &);

	void _graphFollowsChanged(int);

	void _search();

	void _next();

	void _prev();

	void _searchStop();

	void _clicked(const QModelIndex& i);

	void _onCustomContextMenu(const QPoint &);

private slots:

	void _searchEdit(int);
};

#endif // _KS_TRACEVIEW_H
