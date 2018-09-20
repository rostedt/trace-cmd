// SPDX-License-Identifier: LGPL-2.1

/*
 * Copyright (C) 2018 VMware Inc, Yordan Karadzhov <y.karadz@gmail.com>
 */

/**
 *  @file    SchedEvents.cpp
 *  @brief   Defines a callback function for Sched events used to plot in green
 *	     the wake up latency of the task and in red the time the task was
 *	     preempted by another task.
 */

// C++
#include<iostream>

// C++ 11
#include<functional>

// KernelShark
#include "libkshark.h"
#include "plugins/sched_events.h"
#include "KsPlotTools.hpp"
#include "KsPlugins.hpp"

//! @cond Doxygen_Suppress

#define PLUGIN_MIN_BOX_SIZE 4

#define PLUGIN_MAX_ENTRIES_PER_BIN 500

//! @endcond

extern struct plugin_sched_context *plugin_sched_context_handler;

static int plugin_get_wakeup_pid(kshark_context *kshark_ctx,
				 plugin_sched_context *plugin_ctx,
				 const struct kshark_entry *e)
{
	struct tep_record *record;
	unsigned long long val;

	record = kshark_read_at(kshark_ctx, e->offset);
	tep_read_number_field(plugin_ctx->sched_wakeup_pid_field,
			      record->data, &val);
	free_record(record);

	return val;
}

/** Sched Event identifier. */
enum class SchedEvent {
	/** Sched Switch Event. */
	Switch,

	/** Sched Wakeup Event. */
	Wakeup,
};

static void pluginDraw(plugin_sched_context *plugin_ctx,
		       kshark_context *kshark_ctx,
		       kshark_trace_histo *histo,
		       kshark_entry_collection *col,
		       SchedEvent e,
		       int pid,
		       KsPlot::Graph *graph,
		       KsPlot::PlotObjList *shapes)
{
	std::function<void(int)> ifSchedBack;
	KsPlot::Rectangle *rec = nullptr;
	int height = graph->getHeight() * .3;

	auto openBox = [&] (const KsPlot::Point &p)
	{
		/*
		 * First check if we already have an open box. If we don't
		 * have, open a new one.
		 */
		if (!rec)
			rec = new KsPlot::Rectangle;

		rec->setFill(false);
		rec->setPoint(0, p.x() - 1, p.y() - height);
		rec->setPoint(1, p.x() - 1, p.y() - 1);
	};

	auto closeBox = [&] (const KsPlot::Point &p)
	{
		if (rec == nullptr)
			return;

		int boxSize = rec->getPoint(0)->x;
		if (boxSize < PLUGIN_MIN_BOX_SIZE) {
			/* This box is too small. Don't try to plot it. */
			delete rec;
			rec = nullptr;
			return;
		}

		rec->setPoint(3, p.x() - 1, p.y() - height);
		rec->setPoint(2, p.x() - 1, p.y() - 1);

		shapes->push_front(rec);
		rec = nullptr;
	};

	auto lamIfSchSwitchFront = [&] (int bin)
	{
		/*
		 * Starting from the first element in this bin, go forward
		 * in time until you find a trace entry that satisfies the
		 * condition defined by kshark_match_pid.
		 */
		const kshark_entry *entryF =
			ksmodel_get_entry_front(histo, bin, false,
						kshark_match_pid, pid,
						col, nullptr);

		if (entryF &&
		    entryF->pid == pid &&
		    plugin_ctx->sched_switch_event &&
		    entryF->event_id == plugin_ctx->sched_switch_event->id) {
			/*
			 * entryF is sched_switch_event. Close the box and add
			 * it to the list of shapes to be ploted.
			 */
			closeBox(graph->getBin(bin)._base);
		}
	};

	auto lamIfSchWakeupBack = [&] (int bin)
	{
		/*
		 * Starting from the last element in this bin, go backward
		 * in time until you find a trace entry that satisfies the
		 * condition defined by plugin_wakeup_match_pid.
		 */
		const kshark_entry *entryB =
			ksmodel_get_entry_back(histo, bin, false,
					       plugin_wakeup_match_pid, pid,
					       col, nullptr);
		int wakeup_pid;

		if (entryB &&
		    plugin_ctx->sched_wakeup_event &&
		    entryB->event_id == plugin_ctx->sched_wakeup_event->id) {
			wakeup_pid =
				plugin_get_wakeup_pid(kshark_ctx, plugin_ctx, entryB);
			if (wakeup_pid == pid) {
				/*
				 * entryB is a sched_wakeup_event. Open a
				 * green box here.
				 */
				openBox(graph->getBin(bin)._base);

				 /* Green */
				rec->_color = KsPlot::Color(0, 255, 0);
			}
		}
	};

	auto lamIfSchSwitchBack = [&] (int bin)
	{
		/*
		 * Starting from the last element in this bin, go backward
		 * in time until you find a trace entry that satisfies the
		 * condition defined by plugin_switch_match_pid.
		 */
		const kshark_entry *entryB =
			ksmodel_get_entry_back(histo, bin, false,
					       plugin_switch_match_pid, pid,
					       col, nullptr);

		if (entryB &&
		    entryB->pid != pid &&
		    plugin_ctx->sched_switch_event &&
		    entryB->event_id == plugin_ctx->sched_switch_event->id) {
			/*
			 * entryB is a sched_switch_event. Open a
			 * red box here.
			 */
			openBox(graph->getBin(bin)._base);

			/* Red */
			rec->_color = KsPlot::Color(255, 0, 0);
		}
	};

	if (e == SchedEvent::Switch)
		ifSchedBack = lamIfSchSwitchBack;
	else
		ifSchedBack = lamIfSchWakeupBack;

	for (int bin = 0; bin < graph->size(); ++bin) {
		/**
		 * Plotting the latencies makes sense only in the case of a
		 * deep zoom. Here we set a naive threshold based on the number
		 * of entries inside the current bin. This cut seems to work
		 * well in all cases I tested so far, but it may result in
		 * unexpected behavior with some unusual trace data-sets.
		 * TODO: find a better criteria for deciding when to start
		 * plotting latencies.
		 */
		if (ksmodel_bin_count(histo, bin) > PLUGIN_MAX_ENTRIES_PER_BIN)
			continue;

		lamIfSchSwitchFront(bin);

		ifSchedBack(bin);
	}

	if (rec)
		delete rec;

	return;
}

/**
 * @brief Plugin's draw function.
 *
 * @param argv_c: A C pointer to be converted to KsCppArgV (C++ struct).
 * @param pid: Process Id.
 * @param draw_action: Draw action identifier.
 *
 * @returns True if the Pid of the entry matches the value of "pid".
 *	    Otherwise false.
 */
void plugin_draw(kshark_cpp_argv *argv_c, int pid, int draw_action)
{
	plugin_sched_context *plugin_ctx;
	kshark_context *kshark_ctx(NULL);
	kshark_entry_collection *col;

	if (draw_action != KSHARK_PLUGIN_TASK_DRAW || pid == 0)
		return;

	plugin_ctx = plugin_sched_context_handler;
	if (!plugin_ctx || !kshark_instance(&kshark_ctx))
		return;

	KsCppArgV *argvCpp = KS_ARGV_TO_CPP(argv_c);

	/*
	 * Try to find a collections for this task. It is OK if
	 * coll = NULL.
	 */
	col = kshark_find_data_collection(kshark_ctx->collections,
					  kshark_match_pid, pid);

	try {
		pluginDraw(plugin_ctx, kshark_ctx,
			   argvCpp->_histo, col,
			   SchedEvent::Switch, pid,
			   argvCpp->_graph, argvCpp->_shapes);

		pluginDraw(plugin_ctx, kshark_ctx,
			   argvCpp->_histo, col,
			   SchedEvent::Wakeup, pid,
			   argvCpp->_graph, argvCpp->_shapes);
	} catch (const std::exception &exc) {
		std::cerr << "Exception in SchedEvents\n" << exc.what();
	}
}
