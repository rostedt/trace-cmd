// SPDX-License-Identifier: LGPL-2.1

/*
 * Copyright (C) 2017 VMware Inc, Yordan Karadzhov <ykaradzhov@vmware.com>
 */

/**
 *  @file    KsTraceViewer.cpp
 *  @brief   KernelShark Trace Viewer widget.
 */

// C++11
#include <thread>
#include <future>

// KernelShark
#include "KsTraceViewer.hpp"
#include "KsWidgetsLib.hpp"

/** Create a default (empty) Trace viewer widget. */
KsTraceViewer::KsTraceViewer(QWidget *parent)
: QWidget(parent),
  _view(this),
  _model(this),
  _proxyModel(this),
  _tableHeader(_model.header()),
  _toolbar(this),
  _labelSearch("Search: Column", this),
  _labelGrFollows("Graph follows  ", this),
  _columnComboBox(this),
  _selectComboBox(this),
  _searchLineEdit(this),
  _prevButton("Prev", this),
  _nextButton("Next", this),
  _searchStopButton(QIcon::fromTheme("process-stop"), "", this),
  _pbAction(nullptr),
  _graphFollowsCheckBox(this),
  _searchProgBar(this),
  _searchCountLabel("", this),
  _searchDone(false),
  _graphFollows(true),
  _mState(nullptr),
  _data(nullptr)
{
	int bWidth;

	this->setSizePolicy(QSizePolicy::Preferred, QSizePolicy::Maximum);

	/* Make a search toolbar. */
	_toolbar.setOrientation(Qt::Horizontal);
	_toolbar.setMaximumHeight(FONT_HEIGHT * 1.75);

	/* On the toolbar make two Combo boxes for the search settings. */
	_toolbar.addWidget(&_labelSearch);
	_columnComboBox.addItems(_tableHeader);

	/*
	 * Using the old Signal-Slot syntax because
	 * QComboBox::currentIndexChanged has overloads.
	 */
	connect(&_columnComboBox,	SIGNAL(currentIndexChanged(int)),
		this,			SLOT(_searchEdit(int)));

	_toolbar.addWidget(&_columnComboBox);

	_selectComboBox.addItem("contains");
	_selectComboBox.addItem("full match");
	_selectComboBox.addItem("does not have");

	/*
	 * Using the old Signal-Slot syntax because
	 * QComboBox::currentIndexChanged has overloads.
	 */
	connect(&_selectComboBox,	SIGNAL(currentIndexChanged(int)),
		this,			SLOT(_searchEdit(int)));

	_toolbar.addWidget(&_selectComboBox);

	/* On the toolbar, make a Line edit field for search. */
	_searchLineEdit.setMaximumWidth(FONT_WIDTH * 20);

	connect(&_searchLineEdit,	&QLineEdit::returnPressed,
		this,			&KsTraceViewer::_search);

	connect(&_searchLineEdit,	&QLineEdit::textEdited,
		this,			&KsTraceViewer::_searchEditText);

	_toolbar.addWidget(&_searchLineEdit);
	_toolbar.addSeparator();

	/* On the toolbar, add Prev & Next buttons. */
	bWidth = FONT_WIDTH * 6;

	_nextButton.setFixedWidth(bWidth);
	_toolbar.addWidget(&_nextButton);
	connect(&_nextButton,	&QPushButton::pressed,
		this,		&KsTraceViewer::_next);

	_prevButton.setFixedWidth(bWidth);
	_toolbar.addWidget(&_prevButton);
	connect(&_prevButton,	&QPushButton::pressed,
		this,		&KsTraceViewer::_prev);

	_toolbar.addSeparator();
	_searchProgBar.setMaximumWidth(FONT_WIDTH * 10);
	_searchProgBar.setRange(0, 200);
	_pbAction = _toolbar.addWidget(&_searchProgBar);
	_pbAction->setVisible(false);
	_toolbar.addWidget(&_searchCountLabel);
	_searchStopAction = _toolbar.addWidget(&_searchStopButton);
	_searchStopAction->setVisible(false);
	connect(&_searchStopButton,	&QPushButton::pressed,
		this,			&KsTraceViewer::_searchStop);

	/*
	 * On the toolbar, make a Check box for connecting the search pannel
	 * to the Graph widget.
	 */
	_toolbar.addSeparator();
	_toolbar.addWidget(&_graphFollowsCheckBox);
	_toolbar.addWidget(&_labelGrFollows);
	_graphFollowsCheckBox.setCheckState(Qt::Checked);
	connect(&_graphFollowsCheckBox,	&QCheckBox::stateChanged,
		this,			&KsTraceViewer::_graphFollowsChanged);

	/* Initialize the trace viewer. */
	_view.horizontalHeader()->setDefaultAlignment(Qt::AlignLeft);
	_view.verticalHeader()->setVisible(false);
	_view.setEditTriggers(QAbstractItemView::NoEditTriggers);
	_view.setSelectionBehavior(QAbstractItemView::SelectRows);
	_view.setSelectionMode(QAbstractItemView::SingleSelection);
	_view.verticalHeader()->setDefaultSectionSize(FONT_HEIGHT * 1.25);

	 _proxyModel.setSource(&_model);
	_view.setModel(&_proxyModel);
	connect(&_proxyModel, &QAbstractItemModel::modelReset,
		this, &KsTraceViewer::_searchReset);

	_view.setContextMenuPolicy(Qt::CustomContextMenu);
	connect(&_view,	&QTableView::customContextMenuRequested,
		this,	&KsTraceViewer::_onCustomContextMenu);

	connect(&_view,	&QTableView::clicked,
		this,	&KsTraceViewer::_clicked);

	/* Set the layout. */
	_layout.addWidget(&_toolbar);
	_layout.addWidget(&_view);
	this->setLayout(&_layout);
}

/**
 * @brief Load and show trace data.
 *
 * @param data: Input location for the KsDataStore object.
 *	  KsDataStore::loadDataFile() must be called first.
 */
void KsTraceViewer::loadData(KsDataStore *data)
{
	_data = data;
	_model.reset();
	_proxyModel.fill(data);
	_model.fill(data);
	this->_resizeToContents();

	this->setMinimumHeight(SCREEN_HEIGHT / 5);
}

/** Connect the QTableView widget and the State machine of the Dual marker. */
void KsTraceViewer::setMarkerSM(KsDualMarkerSM *m)
{
	QString styleSheetA, styleSheetB;

	_mState = m;
	_model.setColors(_mState->markerA()._color,
			 _mState->markerB()._color);

	/*
	 * Assign a property to State A of the Dual marker state machine. When
	 * the marker is in State A the background color of the selected row
	 * will be the same as the color of Marker A.
	 */
	styleSheetA = "selection-background-color : " +
		      _mState->markerA()._color.name() + ";";

	_mState->stateAPtr()->assignProperty(&_view, "styleSheet",
						     styleSheetA);

	/*
	 * Assign a property to State B. When the marker is in State B the
	 * background color of the selected row will be the same as the color
	 * of Marker B.
	 */
	styleSheetB = "selection-background-color : " +
		      _mState->markerB()._color.name() + ";";

	_mState->stateBPtr()->assignProperty(&_view, "styleSheet",
						     styleSheetB);
}

/** Reset (empty) the table. */
void KsTraceViewer::reset()
{
	this->setMinimumHeight(FONT_HEIGHT * 10);
	_model.reset();
	_resizeToContents();
}

void KsTraceViewer::_searchReset()
{
	_searchProgBar.setValue(0);
	_searchCountLabel.setText("");
	_proxyModel.searchProgress();
	_searchDone = false;
}

/** Get the index of the first (top) visible row. */
size_t  KsTraceViewer::getTopRow() const
{
	return _view.indexAt(_view.rect().topLeft()).row();
}

/** Position given row at the top of the table. */
void  KsTraceViewer::setTopRow(size_t r)
{
	_view.scrollTo(_proxyModel.index(r, 0),
		       QAbstractItemView::PositionAtTop);
}

/** Update the content of the table. */
void KsTraceViewer::update(KsDataStore *data)
{
	/* The Proxy model has to be updated first! */
	_proxyModel.fill(data);
	_model.update(data);
	_data = data;
	if (_mState->activeMarker()._isSet)
		showRow(_mState->activeMarker()._pos, true);
}

void KsTraceViewer::_onCustomContextMenu(const QPoint &point)
{
	QModelIndex i = _view.indexAt(point);

	if (i.isValid()) {
		/*
		 * Use the index of the proxy model to retrieve the value
		 * of the row number in the source model.
		 */
		size_t row = _proxyModel.mapRowFromSource(i.row());
		KsQuickEntryMenu menu(_data, row, this);

		connect(&menu,	&KsQuickEntryMenu::plotTask,
			this,	&KsTraceViewer::plotTask);

		menu.exec(mapToGlobal(point));
	}
}

void KsTraceViewer::_searchEdit(int index)
{
	_searchReset(); // The search has been modified.
}

void KsTraceViewer::_searchEditText(const QString &text)
{
	_searchReset(); // The search has been modified.
}

void KsTraceViewer::_graphFollowsChanged(int state)
{
	_graphFollows = (bool) state;

	if (_graphFollows && _searchDone)
		emit select(*_it); // Send a signal to the Graph widget.
}

static bool notHaveCond(QString searchText, QString itemText)
{
	return !itemText.contains(searchText, Qt::CaseInsensitive);
}

static bool containsCond(QString searchText, QString itemText)
{
	return itemText.contains(searchText, Qt::CaseInsensitive);
}

static bool matchCond(QString searchText, QString itemText)
{
	return (itemText.compare(searchText, Qt::CaseInsensitive) == 0);
}

void KsTraceViewer::_search()
{
	/* Disable the user input until the search is done. */
	_searchLineEdit.setReadOnly(true);
	if (!_searchDone) {
		int xColumn, xSelect;
		QString xText;

		/*
		 * The search is not done. This means that the search settings
		 * have been modified since the last time we searched.
		 */
		_matchList.clear();
		xText = _searchLineEdit.text();
		xColumn = _columnComboBox.currentIndex();
		xSelect = _selectComboBox.currentIndex();

		switch (xSelect) {
			case Condition::Containes:
				_searchItems(xColumn, xText, &containsCond);
				break;

			case Condition::Match:
				_searchItems(xColumn, xText, &matchCond);
				break;

			case Condition::NotHave:
				_searchItems(xColumn, xText, &notHaveCond);
				break;

			default:
				break;
		}

		if (!_matchList.empty()) {
			this->showRow(*_it, true);

			if (_graphFollows)
				emit select(*_it); // Send a signal to the Graph widget.
		}
	} else {
		/*
		 * If the search is done, pressing "Enter" is equivalent
		 * to pressing "Next" button.
		 */
		this->_next();
	}

	/* Enable the user input. */
	_searchLineEdit.setReadOnly(false);
}

void KsTraceViewer::_next()
{
	if (!_searchDone) {
		_search();
		return;
	}

	if (!_matchList.empty()) { // Items have been found.
		++_it; // Move the iterator.
		if (_it == _matchList.end() ) {
			// This is the last item of the list. Go back to the beginning.
			_it = _matchList.begin();
		}

		// Select the row of the item.
		showRow(*_it, true);

		if (_graphFollows)
			emit select(*_it); // Send a signal to the Graph widget.
	}
}

void KsTraceViewer::_prev()
{
	if (!_searchDone) {
		_search();
		return;
	}

	if (!_matchList.empty()) { // Items have been found.
		if (_it == _matchList.begin()) {
			// This is the first item of the list. Go to the last item.
			_it = _matchList.end() - 1;
		} else {
			--_it; // Move the iterator.
		}

		// Select the row of the item.
		showRow(*_it, true);

		if (_graphFollows)
			emit select(*_it); // Send a signal to the Graph widget.
	}
}

void KsTraceViewer::_searchStop()
{
	_searchStopAction->setVisible(false);
	_proxyModel.searchStop();
}

void KsTraceViewer::_clicked(const QModelIndex& i)
{
	if (_graphFollows) {
		/*
		 * Use the index of the proxy model to retrieve the value
		 * of the row number in the base model.
		 */
		size_t row = _proxyModel.mapRowFromSource(i.row());
		emit select(row); // Send a signal to the Graph widget.
	}
}

/** Make a given row of the table visible. */
void KsTraceViewer::showRow(size_t r, bool mark)
{
	/*
	 * Use the index in the source model to retrieve the value of the row number
	 * in the proxy model.
	 */
	QModelIndex index = _proxyModel.mapFromSource(_model.index(r, 0));

	if (mark) { // The row will be selected (colored).
		/* Get the first and the last visible rows of the table. */
		int visiTot = _view.indexAt(_view.rect().topLeft()).row();
		int visiBottom = _view.indexAt(_view.rect().bottomLeft()).row() - 2;

		/* Scroll only if the row to be shown in not vizible. */
		if (index.row() < visiTot || index.row() > visiBottom)
			_view.scrollTo(index, QAbstractItemView::PositionAtCenter);

		_view.selectRow(index.row());
	} else {
		/*
		 * Just make sure that the row is visible. It will show up at
		 * the top of the visible part of the table.
		 */
		_view.scrollTo(index, QAbstractItemView::PositionAtTop);
	}
}

/** Deselects the selected items (row) if any. */
void KsTraceViewer::deselect()
{
	_view.clearSelection();
}

/** Switch the Dual marker. */
void KsTraceViewer::markSwitch()
{
	/* The state of the Dual marker has changed. Get the new active marker. */
	DualMarkerState state = _mState->getState();

	/* First deal with the passive marker. */
	if (_mState->getMarker(!state)._isSet) {
		/*
		 * The passive marker is set. Use the model to color the row of
		 * the passive marker.
		 */
		_model.selectRow(!state, _mState->getMarker(!state)._pos);
	}
	else {
		/*
		 * The passive marker is not set.
		 * Make sure that the model colors nothing.
		 */
		_model.selectRow(!state, -1);
	}

	/*
	 * Now deal with the active marker. This has to be done after dealing
	 *  with the model, because changing the model clears the selection.
	 */
	if (_mState->getMarker(state)._isSet) {
		/*
		 * The active marker is set. Use QTableView to select its row.
		 * The index in the source model is used to retrieve the value
		 * of the row number in the proxy model.
		 */
		size_t row =_mState->getMarker(state)._pos;

		QModelIndex index = _proxyModel.mapFromSource(_model.index(row, 0));

		/*
		 * The row of the active marker will be colored according to
		 * the assigned property of the current state of the Dual marker.
		 */
		_view.selectRow(index.row());
	} else {
		_view.clearSelection();
	}
}

/**
 * Reimplemented event handler used to update the geometry of the widget on
 * resize events.
 */
void KsTraceViewer::resizeEvent(QResizeEvent* event)
{
	int nColumns = _tableHeader.count();
	int tableSize(0), viewSize, freeSpace;

	for (int c = 0; c < nColumns; ++c) {
		tableSize += _view.columnWidth(c);
	}

	viewSize = _view.width() -
		   qApp->style()->pixelMetric(QStyle::PM_ScrollBarExtent);

	if ((freeSpace = viewSize - tableSize) > 0) {
		_view.setColumnWidth(nColumns - 1, _view.columnWidth(nColumns - 1) +
						   freeSpace -
						   2); /* Just a little bit less space.
							* This will allow the scroll bar
							* to disappear when the widget
							* is extended to maximum. */
	}
}

/**
 * Reimplemented event handler used to move the active marker.
 */
void KsTraceViewer::keyReleaseEvent(QKeyEvent *event)
{
	if (event->key() == Qt::Key_Up || event->key() == Qt::Key_Down) {
		QItemSelectionModel *sm = _view.selectionModel();
		if (sm->hasSelection()) {
			/* Only one row at the time can be selected. */
			int row = sm->selectedRows()[0].row();
			emit select(row); // Send a signal to the Graph widget.
		}

		return;
	}

	QWidget::keyReleaseEvent(event);
}

void KsTraceViewer::_resizeToContents()
{
	int rows, columnSize;

	_view.setVisible(false);
	_view.resizeColumnsToContents();
	_view.setVisible(true);

	/*
	 * Because of some unknown reason the first column doesn't get
	 * resized properly by the code above. We will resize this
	 * column by hand.
	 */
	rows = _model.rowCount({});
	columnSize = STRING_WIDTH(QString("%1").arg(rows)) + FONT_WIDTH;
	_view.setColumnWidth(0, columnSize);
}

size_t KsTraceViewer::_searchItems(int column,
				   const QString &searchText,
				   condition_func cond)
{
	int count;

	_searchProgBar.show();
	_pbAction->setVisible(true);

	if (column == KsViewModel::TRACE_VIEW_COL_INFO ||
	    column == KsViewModel::TRACE_VIEW_COL_LAT) {
		_searchStopAction->setVisible(true);
		_proxyModel.search(column, searchText, cond, &_matchList,
				   &_searchProgBar, &_searchCountLabel);

		_searchStopAction->setVisible(false);
	} else {
		_searchItemsMapReduce(column, searchText, cond);
	}

	count = _matchList.count();

	_pbAction->setVisible(false);
	_searchCountLabel.setText(QString(" %1").arg(count));
	_searchDone = true;

	if (count == 0) // No items have been found. Do nothing.
		return 0;

	QItemSelectionModel *sm = _view.selectionModel();
	if (sm->hasSelection()) {
		/* Only one row at the time can be selected. */
		int row = sm->selectedRows()[0].row();

		_view.clearSelection();
		_it = _matchList.begin();
		/*
		 * Move the iterator to the first element of the match list
		 * after the selected one.
		 */
		while (*_it <= row) {
			++_it;  // Move the iterator.
			if (_it == _matchList.end()) {
				/*
				 * This is the last item of the list. Go back
				 * to the beginning.
				 */
				_it = _matchList.begin();
				break;
			}
		}
	} else {
		/* Move the iterator to the beginning of the match list. */
		_view.clearSelection();
		_it = _matchList.begin();
	}

	return count;
}

void KsTraceViewer::_searchItemsMapReduce(int column,
					  const QString &searchText,
					  condition_func cond)
{
	int nThreads = std::thread::hardware_concurrency();
	std::vector<QPair<int, int>> ranges(nThreads);
	std::vector<std::future<QList<int>>> maps;
	int i(0), nRows(_proxyModel.rowCount({}));
	int delta(nRows / nThreads);

	auto lamSearchMap = [&] (const QPair<int, int> &range,
				 bool notify) {
		return _proxyModel.searchMap(column, searchText, cond,
					     range.first, range.second,
					     notify);
	};

	auto lamSearchReduce = [&] (QList<int> &resultList,
				  const QList<int> &mapList) {
		resultList << mapList;
		_searchProgBar.setValue(_searchProgBar.value() + 1);
	};

	for (auto &r: ranges) {
		r.first = (i++) * delta;
		r.second = r.first + delta - 1;
	}

	/*
	 * If the range is not multiple of the number of threads, adjust
	 * the last range interval.
	 */
	ranges.back().second = nRows - 1;
	maps.push_back(std::async(lamSearchMap, ranges[0], true));
	for (int r = 1; r < nThreads; ++r)
		maps.push_back(std::async(lamSearchMap, ranges[r], false));

	while (_proxyModel.searchProgress() < KS_PROGRESS_BAR_MAX- nThreads) {
		std::unique_lock<std::mutex> lk(_proxyModel._mutex);
		_proxyModel._pbCond.wait(lk);
		_searchProgBar.setValue(_proxyModel.searchProgress());
		QApplication::processEvents();
	}

	for (auto &m: maps)
		lamSearchReduce(_matchList, m.get());
}
