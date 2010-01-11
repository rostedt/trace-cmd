#define _GNU_SOURCE
#include <gtk/gtk.h>
#include <getopt.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "trace-cmd.h"
#include "trace-graph.h"
#include "trace-filter.h"

#define version "0.1.1"

#define TRACE_WIDTH	800
#define TRACE_HEIGHT	600

#define default_input_file "trace.dat"
static char *input_file;
static struct graph_info *ginfo;

void usage(char *prog)
{
	printf("Usage: %s\n", prog);
	printf("  -h	Display this help message\n");
	printf("  -i	input_file, default is %s\n", default_input_file);
}

static struct tracecmd_input *read_tracecmd(gchar *filename)
{
	struct tracecmd_input *handle;

	handle = tracecmd_open(filename);

	if (!handle) {
		warning("can not load %s", filename);
		return NULL;
	}

	if (tracecmd_read_headers(handle) < 0) {
		warning("can not read %s headers", filename);
		goto failed;
	}

	if (tracecmd_init_data(handle) < 0) {
		warning("can not init %s", filename);
		goto failed;
	}

	return handle;

 failed:
	tracecmd_close(handle);
	return NULL;
}

/* Callback for the clicked signal of the Load button */
static void
load_clicked (gpointer data)
{
	struct graph_info *ginfo = data;
	struct tracecmd_input *handle;
	GtkWidget *dialog;
	gchar *filename;

	dialog = gtk_file_chooser_dialog_new("Load File",
					     NULL,
					     GTK_FILE_CHOOSER_ACTION_OPEN,
					     GTK_STOCK_CANCEL, GTK_RESPONSE_CANCEL,
					     GTK_STOCK_OPEN, GTK_RESPONSE_ACCEPT,
					     NULL);
	if (gtk_dialog_run(GTK_DIALOG(dialog)) == GTK_RESPONSE_ACCEPT) {
		filename = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(dialog));
		handle = read_tracecmd(filename);
		if (handle)
			trace_graph_load_handle(ginfo, handle);
		g_free(filename);
	}
	gtk_widget_destroy(dialog);
}

/* Callback for the clicked signal of the Exit button */
static void
exit_clicked (GtkWidget *widget, gpointer data)
{
	gtk_widget_destroy (GTK_WIDGET (data)); /* the user data points to the main window */
	tracecmd_close(ginfo->handle);
	gtk_main_quit ();
}

/* Callback for the delete_event signal of the main application window */
static gint
delete_event (GtkWidget *widget, GdkEvent *event, gpointer data)
{
	gtk_widget_destroy (widget); /* destroy the main window */
	tracecmd_close(ginfo->handle);
	gtk_main_quit ();
	return TRUE;
}

/* Callback for the clicked signal of the Events filter button */
static void
events_clicked (gpointer data)
{
	struct graph_info *ginfo = data;
	gboolean all_events = TRUE;
	gchar **systems = NULL;
	gint *events = NULL;

	if (!ginfo->handle)
		return;

	all_events = ginfo->all_events;
	systems = ginfo->systems;
	events = ginfo->event_ids;

	trace_filter_event_dialog(ginfo->handle, all_events,
				  systems, events,
				  trace_graph_event_filter_callback, ginfo);
}

void trace_graph(int argc, char **argv)
{
	struct tracecmd_input *handle = NULL;
	struct stat st;
	GtkWidget *window;
	GtkWidget *vbox;
	GtkWidget *hbox;
	GtkWidget *menu_bar;
	GtkWidget *menu;
	GtkWidget *menu_item;
	GtkWidget *sub_item;
	GtkWidget *widget;
	int c;
	int ret;

	while ((c = getopt(argc, argv, "hi:")) != -1) {
		switch(c) {
		case 'h':
			usage(basename(argv[0]));
			return;
		case 'i':
			input_file = optarg;
			break;
		default:
			/* assume the other options are for gtk */
			break;
		}
	}

	if (!input_file) {
		ret = stat(default_input_file, &st);
		if (ret >= 0)
			input_file = default_input_file;
	}

	if (input_file)
		handle = read_tracecmd(input_file);

	gtk_init(&argc, &argv);

	/* graph struct is used by handlers */
	ginfo = trace_graph_create(handle);

	/* --- Main window --- */

	window = gtk_window_new(GTK_WINDOW_TOPLEVEL);

	/* --- Top Level Vbox --- */

	vbox = gtk_vbox_new(FALSE, 0);
	gtk_container_add(GTK_CONTAINER (window), vbox);
	gtk_widget_show(vbox);

	/* --- Menu Bar --- */

	menu_bar = gtk_menu_bar_new();
	gtk_box_pack_start(GTK_BOX (vbox), menu_bar, FALSE, FALSE, 0);
	gtk_widget_show(menu_bar);

	/* --- File Option --- */

	menu_item = gtk_menu_item_new_with_label("File");
	gtk_widget_show(menu_item);

	gtk_menu_bar_append(GTK_MENU_BAR (menu_bar), menu_item);

	menu = gtk_menu_new();    /* Don't need to show menus */


	/* --- File - Load Option --- */

	sub_item = gtk_menu_item_new_with_label("Load info");

	/* Add them to the menu */
	gtk_menu_shell_append(GTK_MENU_SHELL (menu), sub_item);

	/* We can attach the Quit menu item to our exit function */
	g_signal_connect_swapped (G_OBJECT (sub_item), "activate",
				  G_CALLBACK (load_clicked),
				  (gpointer) ginfo);

	/* We do need to show menu items */
	gtk_widget_show(sub_item);


	/* --- File - Quit Option --- */

	sub_item = gtk_menu_item_new_with_label("Quit");

	/* Add them to the menu */
	gtk_menu_shell_append(GTK_MENU_SHELL (menu), sub_item);

	/* We can attach the Quit menu item to our exit function */
	g_signal_connect_swapped (G_OBJECT (sub_item), "activate",
				  G_CALLBACK (exit_clicked),
				  (gpointer) window);

	/* We do need to show menu items */
	gtk_widget_show(sub_item);


	gtk_menu_item_set_submenu(GTK_MENU_ITEM (menu_item), menu);

	/* --- end File options --- */


	/* --- Filter Option --- */

	menu_item = gtk_menu_item_new_with_label("Filter");
	gtk_widget_show(menu_item);

	gtk_menu_bar_append(GTK_MENU_BAR (menu_bar), menu_item);

	menu = gtk_menu_new();    /* Don't need to show menus */


	/* --- Filter - Events Option --- */

	sub_item = gtk_menu_item_new_with_label("events");

	/* Add them to the menu */
	gtk_menu_shell_append(GTK_MENU_SHELL (menu), sub_item);

	/* We can attach the Quit menu item to our exit function */
	g_signal_connect_swapped (G_OBJECT (sub_item), "activate",
				  G_CALLBACK (events_clicked),
				  (gpointer) ginfo);

	/* We do need to show menu items */
	gtk_widget_show(sub_item);


	/* --- End Filter Options --- */
	gtk_menu_item_set_submenu(GTK_MENU_ITEM (menu_item), menu);


	/* --- Top Level Hbox --- */

	hbox = gtk_hbox_new(FALSE, 0);
	gtk_box_pack_start(GTK_BOX(vbox), hbox, TRUE, TRUE, 0);
	gtk_widget_show(hbox);


	/* --- Set up the Graph --- */

	widget = trace_graph_get_window(ginfo);
	gtk_box_pack_start(GTK_BOX (hbox), widget, TRUE, TRUE, 0);
	gtk_widget_show(widget);


	/**********************************************
	 *   Main Window
	 **********************************************/

	/* Connect to the delete_event signal and Run the application */

	gtk_signal_connect (GTK_OBJECT (window), "delete_event",
			    (GtkSignalFunc) delete_event,
			    NULL);

	gtk_widget_set_size_request(window, TRACE_WIDTH, TRACE_HEIGHT);

	gtk_widget_show (window);
	gtk_main ();
}

int main(int argc, char **argv)
{
	trace_graph(argc, argv);
	return 0;
}
