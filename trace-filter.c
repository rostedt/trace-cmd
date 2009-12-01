#include <gtk/gtk.h>
#include <string.h>

#include "trace-cmd.h"
#include "trace-local.h"
#include "trace-view-store.h"

#define EVENT_DIALOG_WIDTH	400
#define EVENT_DIALOG_HEIGHT	600

struct dialog_helper {
	GtkWidget		*dialog;
	GtkWidget		*trace_tree;
};

enum {
	COL_EVENT,
	NUM_EVENT_COLS,
};

static GtkTreeModel *
create_tree_event_model(GtkWidget *tree_view)
{
	GtkTreeModel *model;
	TraceViewStore *trace_view;
	GtkTreeStore *treestore;
	GtkTreeIter iter_all, iter_sys, iter_events;
	struct pevent *pevent;
	struct event **events;
	struct event *event;
	char *last_system = NULL;
	gint i;

	model = gtk_tree_view_get_model(GTK_TREE_VIEW(tree_view));
	trace_view = TRACE_VIEW_STORE(model);

	pevent = tracecmd_get_pevent(trace_view->handle);

	treestore = gtk_tree_store_new(NUM_EVENT_COLS, G_TYPE_STRING);

	gtk_tree_store_append(treestore, &iter_all, NULL);
	gtk_tree_store_set(treestore, &iter_all,
			   COL_EVENT,	"All",
			   -1);

	events = pevent_list_events(pevent, EVENT_SORT_SYSTEM);
	if (!event)
		return GTK_TREE_MODEL(treestore);

	for (i = 0; events[i]; i++) {
		event = events[i];
		if (!last_system || strcmp(last_system, event->system) != 0) {
			gtk_tree_store_append(treestore, &iter_sys, &iter_all);
			gtk_tree_store_set(treestore, &iter_sys,
					   COL_EVENT, event->system,
					   -1);
			last_system = event->system;
		}

		gtk_tree_store_append(treestore, &iter_events, &iter_sys);
		gtk_tree_store_set(treestore, &iter_events,
				   COL_EVENT, event->name,
				   -1);

	}

	return GTK_TREE_MODEL(treestore);
}

static GtkWidget *create_event_list_view(GtkWidget *tree_view)
{
	GtkTreeViewColumn *col;
	GtkCellRenderer *renderer;
	GtkWidget *view;
	GtkTreeModel *model;

	view = gtk_tree_view_new();

	/* --- events column --- */

	col = gtk_tree_view_column_new();

	gtk_tree_view_column_set_title(col, "Events");

	gtk_tree_view_append_column(GTK_TREE_VIEW(view), col);

	renderer  = gtk_cell_renderer_text_new();

	gtk_tree_view_column_pack_start(col, renderer, TRUE);

	gtk_tree_view_column_add_attribute(col, renderer, "text", COL_EVENT);

	model = create_tree_event_model(tree_view);

	gtk_tree_view_set_model(GTK_TREE_VIEW(view), model);

	g_object_unref(model);

	gtk_tree_selection_set_mode(gtk_tree_view_get_selection(GTK_TREE_VIEW(view)),
				    GTK_SELECTION_MULTIPLE);

	gtk_tree_view_expand_all(GTK_TREE_VIEW(view));

	return view;
}


/* Callback for the clicked signal of the Events filter button */
static void
event_dialog_response (gpointer data, gint response_id)
{
	struct dialog_helper *helper = data;

	switch (response_id) {
	case GTK_RESPONSE_ACCEPT:
		printf("accept!\n");
		break;
	case GTK_RESPONSE_REJECT:
		printf("reject!\n");
		break;
	default:
		break;
	};

	gtk_widget_destroy(GTK_WIDGET(helper->dialog));

	g_free(helper);
}

void trace_filter_event_dialog(void *trace_tree)
{
	GtkWidget *tree_view = GTK_WIDGET(trace_tree);
	struct dialog_helper *helper;
	GtkWidget *dialog;
	GtkWidget *scrollwin;
	GtkWidget *view;

//	trace_view = gtk_tree_view_get_model(GTK_TREE_VIEW(tree_view));

	helper = g_malloc(sizeof(*helper));

	/* --- Make dialog window --- */

	dialog = gtk_dialog_new_with_buttons("Filter Events",
					     NULL,
					     GTK_DIALOG_MODAL,
					     "Accept",
					     GTK_RESPONSE_ACCEPT,
					     GTK_STOCK_CANCEL,
					     GTK_RESPONSE_REJECT,
					     NULL);

	helper->dialog = dialog;
	helper->trace_tree = tree_view;

	/* We can attach the Quit menu item to our exit function */
	g_signal_connect_swapped (dialog, "response",
				  G_CALLBACK (event_dialog_response),
				  (gpointer) helper);

	scrollwin = gtk_scrolled_window_new(NULL, NULL);
	view = create_event_list_view(tree_view);

	gtk_box_pack_start(GTK_BOX(GTK_DIALOG(dialog)->vbox), scrollwin, TRUE, TRUE, 0);
	gtk_container_add(GTK_CONTAINER(scrollwin), view);

	gtk_widget_set_size_request(GTK_WIDGET(dialog),
				    EVENT_DIALOG_WIDTH, EVENT_DIALOG_HEIGHT);

	gtk_widget_show_all(dialog);
}
