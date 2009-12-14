/*
 * Copyright (C) 2009, Steven Rostedt <srostedt@redhat.com>
 *
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 2 of the License (not later!)
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 */
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <fcntl.h>
#include <unistd.h>
#include <gnome.h>
#include <gtk/gtk.h>

#include "trace-cmd.h"
#include "trace-local.h"
#include "trace-graph.h"

#define version "0.1.1"

#define TRACE_WIDTH	800
#define TRACE_HEIGHT	600

#define input_file "trace.dat"

#define CPU_MIDDLE(cpu) (80 * (cpu) + 80)
#define CPU_TOP(cpu) (CPU_MIDDLE(cpu) - 10)
#define CPU_BOTTOM(cpu) (CPU_MIDDLE(cpu) + 10)

static void convert_nano(unsigned long long time, unsigned long *sec,
			 unsigned long *usec)
{
	*sec = time / 1000000000ULL;
	*usec = (time / 1000) % 1000000;
}

static void update_with_backend(struct graph_info *ginfo,
				gint x, gint y,
				gint width, gint height)
{
	gdk_draw_drawable(ginfo->draw->window,
			  ginfo->draw->style->fg_gc[GTK_WIDGET_STATE(ginfo->draw)],
			  ginfo->curr_pixmap,
			  x, y, x, y,
			  width, height);
}

static gboolean
expose_event(GtkWidget *widget, GdkEventExpose *event, gpointer data)
{
	struct graph_info *ginfo = data;

	update_with_backend(ginfo,
			    event->area.x, event->area.y,
			    event->area.width, event->area.height);

	return FALSE;
}

static void start_line(GtkWidget *widget, gint x, gint y, gpointer data)
{
	struct graph_info *ginfo = data;

	ginfo->last_x = x;
	ginfo->last_y = y;

	ginfo->mov_w = 0;
	ginfo->mov_h = 0;

	printf("x=%d y=%d\n", x, y);
}

static gboolean
button_press_event(GtkWidget *widget, GdkEventButton *event, gpointer data)
{
	struct graph_info *ginfo = data;

	printf("button = %d\n", event->button);

	if ((event->button == 1 || event->button == 3) &&
	    ginfo->curr_pixmap != NULL) {
		if (event->button == 3)
			ginfo->save = TRUE;
		else
			ginfo->save = FALSE;

		ginfo->draw_line = TRUE;
		start_line(widget, event->x, event->y, data);
	}

	return TRUE;
}

static void normalize_xywh(gint *x, gint *y, gint *w, gint *h)
{
	if (*w < 0) {
		*x = *x + *w;
		*w *= -1;
	}

	if (*h < 0) {
		*y = *y + *h;
		*h *= -1;
	}
}

static void clear_last_line(GtkWidget *widget, struct graph_info *ginfo)
{
	gint x, y, w, h;

	x = ginfo->last_x;
	y = ginfo->last_y;

	w = ginfo->mov_w;
	h = ginfo->mov_h;

	normalize_xywh(&x, &y, &w, &h);

	w++;
	h++;

	update_with_backend(ginfo, x, y, w, h);
}

static void
draw_line(GtkWidget *widget, gdouble x, gdouble y, struct graph_info *ginfo)
{
	clear_last_line(widget, ginfo);

	ginfo->mov_w = x - ginfo->last_x;
	ginfo->mov_h = y - ginfo->last_y;

	printf("draw %f %f\n", x, y);

	gdk_draw_line(widget->window, widget->style->black_gc,
		      ginfo->last_x, ginfo->last_y,
		      x, y);
}

static void
save_line(GtkWidget *widget, struct graph_info *ginfo)
{
	gint x, y;

	x = ginfo->last_x + ginfo->mov_w;
	y = ginfo->last_y + ginfo->mov_h;

	printf("save %d,%d to %d,%d, width=%d height=%d\n",
	       x,y, ginfo->last_x, ginfo->last_y,
	       ginfo->mov_w, ginfo->mov_h);
	       
	gdk_draw_line(widget->window, widget->style->black_gc,
		      ginfo->last_x, ginfo->last_y,
		      x, y);

	gdk_draw_line(ginfo->curr_pixmap, widget->style->black_gc,
		      ginfo->last_x, ginfo->last_y,
		      x, y);
}

static void print_rec_info(struct record *record, struct pevent *pevent, int cpu)
{
	struct trace_seq s;
	struct event *event;
	unsigned long sec, usec;
	gint type;

	trace_seq_init(&s);

	convert_nano(record->ts, &sec, &usec);
	trace_seq_printf(&s, "%lu.%06lu", sec, usec);

	type = pevent_data_type(pevent, record);
	event = pevent_data_event_from_type(pevent, type);
	trace_seq_puts(&s, event->name);
	trace_seq_putc(&s, ':');
	pevent_event_info(&s, event, cpu, record->data, record->size,
			  record->ts);
	trace_seq_putc(&s, '\n');
	trace_seq_do_printf(&s);
}

#define CPU_BOARDER 5

static void draw_cpu_info(struct graph_info *ginfo, gint cpu, gint x, gint y)
{
	PangoLayout *layout;
	struct record *record = NULL;
	struct pevent *pevent;
	struct event *event;
	guint64 time;
	const char *comm;
	gint pid = -1;
	gint type;
	unsigned long sec, usec;
	struct trace_seq s;
	gint width, height;
	GdkPixmap *pix;
	static GdkGC *pix_bg;

	if (!pix_bg) {
		GdkColor color;

		pix_bg = gdk_gc_new(ginfo->draw->window);
		color.red = (0xff) *(65535/255);
		color.green = (0xfa) *(65535/255);
		color.blue = (0xcd) *(65535/255);
		gdk_color_alloc(gtk_widget_get_colormap(ginfo->draw), &color);
		gdk_gc_set_foreground(pix_bg, &color);
	}

	printf("res=%f\n", ginfo->resolution);
	time =  (x / ginfo->resolution) + ginfo->view_start_time;
	convert_nano(time, &sec, &usec);

	pevent = ginfo->pevent;

	trace_seq_init(&s);

	printf("start=%zu end=%zu time=%lu\n", ginfo->start_time, ginfo->end_time, time);
	tracecmd_set_cpu_to_timestamp(ginfo->handle, cpu, time);
	do {
		if (record)
			free(record);
		record = tracecmd_read_data(ginfo->handle, cpu);
	} while (record && record->ts <= (time - 1 / ginfo->resolution));

	if (record) {
		
		pid = pevent_data_pid(ginfo->pevent, record);
		comm = pevent_data_comm_from_pid(ginfo->pevent, pid);

		printf("record->ts=%llu time=%zu-%zu\n",
		       record->ts, time, time+(gint)(5/ginfo->resolution));
		print_rec_info(record, pevent, cpu);

		if (record->ts < time + 1/ginfo->resolution) {
			convert_nano(record->ts, &sec, &usec);

			type = pevent_data_type(pevent, record);
			event = pevent_data_event_from_type(pevent, type);
			trace_seq_puts(&s, event->name);
			trace_seq_putc(&s, '\n');
			pevent_data_lat_fmt(pevent, &s, record->data, record->size);
			trace_seq_putc(&s, '\n');
			pevent_event_info(&s, event, cpu, record->data, record->size,
					  record->ts);
			trace_seq_putc(&s, '\n');
		}

		trace_seq_printf(&s, "%lu.%06lu", sec, usec);
		if (pid)
			trace_seq_printf(&s, " %s-%d", comm, pid);
		else
			trace_seq_puts(&s, " <idle>");

		free(record);

	} else
		trace_seq_printf(&s, "%lu.%06lu", sec, usec);

	trace_seq_putc(&s, 0);

	layout = gtk_widget_create_pango_layout(ginfo->draw, s.buffer);
	pango_layout_get_pixel_size(layout, &width, &height);

	width += CPU_BOARDER * 2;
	height += CPU_BOARDER * 2;

	if (y > height)
		y -= height;


	if (x + width > ginfo->draw->allocation.width)
		x -= ((x + width) - ginfo->draw->allocation.width);

	ginfo->cpu_data_x = x;
	ginfo->cpu_data_y = y;
	ginfo->cpu_data_w = width;
	ginfo->cpu_data_h = height;

	pix = gdk_pixmap_new(ginfo->draw->window,
			     width,
			     height,
			     -1);

	gdk_draw_rectangle(pix,
			   pix_bg,
			   TRUE,
			   0, 0,
			   width, height);
	
	gdk_draw_rectangle(pix,
			   ginfo->draw->style->black_gc,
			   FALSE,
			   0, 0,
			   width-1, height-1);

	gdk_draw_layout(pix, ginfo->draw->style->black_gc,
			CPU_BOARDER, CPU_BOARDER, layout);
	gdk_draw_drawable(ginfo->draw->window,
			  ginfo->draw->style->fg_gc[GTK_WIDGET_STATE(ginfo->draw)],
			  pix, 0, 0, x, y, width, height);

	g_object_unref(layout);
	g_object_unref(pix);
}

static gboolean
motion_notify_event(GtkWidget *widget, GdkEventMotion *event, gpointer data)
{
	struct graph_info *ginfo = data;
	GdkModifierType state;
	gint x, y;
	gint cpu;

	update_with_backend(ginfo, ginfo->cpu_data_x, ginfo->cpu_data_y,
			    ginfo->cpu_data_w, ginfo->cpu_data_h);
	if (event->is_hint)
		gdk_window_get_pointer(event->window, &x, &y, &state);
	else {
		x = event->x;
		y = event->y;
		state = event->state;
	}

	if (!ginfo->curr_pixmap)
		return TRUE;

	if (ginfo->draw_line) {
		draw_line(widget, x, y, ginfo);
		return TRUE;
	}

	for (cpu = 0; cpu < ginfo->cpus; cpu++) {
		if (y >= CPU_TOP(cpu) && y <= CPU_BOTTOM(cpu)) {
			draw_cpu_info(ginfo, cpu, x, y);
		}
	}

	return TRUE;
}

static gboolean
button_release_event(GtkWidget *widget, GdkEventMotion *event, gpointer data)
{
	struct graph_info *ginfo = data;

	printf("RELEASE %s\n", ginfo->save ? "save" : "");
	clear_last_line(widget, ginfo);

	ginfo->draw_line = FALSE;

	if (ginfo->save)
		save_line(widget, ginfo);

	return TRUE;
}

static gint do_hash(gint val)
{
	return (val + (val << 4) + (val << 8) + (val << 12) + 
		(val << 16) + (val << 20) + (val << 24) +
		(val << 28)) * 3;
}

static void set_color_by_pid(GtkWidget *widget, GdkGC *gc, gint pid)
{
	GdkColor color;
	gint hash = do_hash(pid);
	static gint last_pid = -1;

	if (!(hash & 0xffffff) && last_pid != pid) {
		last_pid = pid;
		printf("pid=%d is black\n", pid);
	}
	color.red = (hash & 0xff)*(65535/255);
	color.blue = ((hash >> 8) & 0xff)*(65535/255);
	color.green = ((hash >> 16) & 0xff)*(65535/255);
	gdk_color_alloc(gtk_widget_get_colormap(widget), &color);
	gdk_gc_set_foreground(gc, &color);
}

static void draw_cpu(struct graph_info *ginfo, gint cpu,
		     gint old_width, gint new_width)
{
	gint height = CPU_MIDDLE(cpu);
	struct record *record;
	static GdkGC *gc;
	guint64 ts;
	gint pid;
	gint x;

	if (!gc)
		gc = gdk_gc_new(ginfo->draw->window);

	gdk_draw_line(ginfo->curr_pixmap, ginfo->draw->style->black_gc,
		      0, height, new_width, height);

	ts = ginfo->view_start_time;

	tracecmd_set_cpu_to_timestamp(ginfo->handle, cpu, ts);

	while ((record = tracecmd_read_data(ginfo->handle, cpu))) {
		if (record->ts > ginfo->view_end_time)
			break;

		ts = record->ts - ginfo->view_start_time;

		x = (gint)((gdouble)ts * ginfo->resolution);

		pid = pevent_data_pid(ginfo->pevent, record);

		set_color_by_pid(ginfo->draw, gc, pid);

		gdk_draw_line(ginfo->curr_pixmap, gc, // ginfo->draw->style->black_gc,
			      x, CPU_TOP(cpu), x, CPU_BOTTOM(cpu));
		free(record);
	}

	if (record)
		free(record);
}


static void draw_timeline(struct graph_info *ginfo, gint width)
{
	PangoLayout *layout;
	struct trace_seq s;
	unsigned long sec, usec;
	unsigned long long time;
	gint mid;
	gint w, h, height;

	mid = width / 2;

	/* --- draw timeline text --- */

	layout = gtk_widget_create_pango_layout(ginfo->draw, "Time Line");
	pango_layout_get_pixel_size(layout, &w, &h);

	height = 10 + h;

	gdk_draw_layout(ginfo->curr_pixmap, ginfo->draw->style->black_gc,
			mid - w / 2, 5, layout);
	g_object_unref(layout);


	/* --- draw time line lines --- */
	gdk_draw_line(ginfo->curr_pixmap, ginfo->draw->style->black_gc,
		      0, height, width, height);

	gdk_draw_line(ginfo->curr_pixmap, ginfo->draw->style->black_gc,
		      0, height, 0, height + 5);

	gdk_draw_line(ginfo->curr_pixmap, ginfo->draw->style->black_gc,
		      width-1, height, width-1, height);

	gdk_draw_line(ginfo->curr_pixmap, ginfo->draw->style->black_gc,
		      width-1, height, width-1, height + 5);

	gdk_draw_line(ginfo->curr_pixmap, ginfo->draw->style->black_gc,
		      mid, height, mid, height + 5);

	height += 10;

	/* --- draw starting time --- */
	convert_nano(ginfo->start_time, &sec, &usec);
	trace_seq_init(&s);
	trace_seq_printf(&s, "%lu.%06lu", sec, usec);

	layout = gtk_widget_create_pango_layout(ginfo->draw, s.buffer);
	pango_layout_get_pixel_size(layout, &w, &h);

	gdk_draw_layout(ginfo->curr_pixmap, ginfo->draw->style->black_gc,
			1, height, layout);
	g_object_unref(layout);


	/* --- draw ending time --- */
	convert_nano(ginfo->end_time, &sec, &usec);
	trace_seq_init(&s);
	trace_seq_printf(&s, "%lu.%06lu", sec, usec);

	layout = gtk_widget_create_pango_layout(ginfo->draw, s.buffer);
	pango_layout_get_pixel_size(layout, &w, &h);

	gdk_draw_layout(ginfo->curr_pixmap, ginfo->draw->style->black_gc,
			width - (w + 2), height, layout);
	g_object_unref(layout);

	/* --- draw middle time --- */
	time = mid / ginfo->resolution + ginfo->view_start_time;

	convert_nano(time, &sec, &usec);
	trace_seq_init(&s);
	trace_seq_printf(&s, "%lu.%06lu", sec, usec);

	layout = gtk_widget_create_pango_layout(ginfo->draw, s.buffer);
	pango_layout_get_pixel_size(layout, &w, &h);

	gdk_draw_layout(ginfo->curr_pixmap, ginfo->draw->style->black_gc,
			mid - (w / 2), height, layout);
	g_object_unref(layout);
}

static void draw_info(struct graph_info *ginfo, gint old_width, gint old_height,
		 gint new_width, gint new_height)
{
	gint cpu;

	ginfo->resolution = (gdouble)new_width / (gdouble)(ginfo->view_end_time -
							   ginfo->view_start_time);

	draw_timeline(ginfo, new_width);

	
	for (cpu = 0; cpu < ginfo->cpus; cpu++)
		draw_cpu(ginfo, cpu, old_width, new_width);

}

static gboolean
configure_event(GtkWidget *widget, GdkEventMotion *event, gpointer data)
{
	struct graph_info *ginfo = data;
	GdkPixmap *old_pix;
	gint old_w, old_h;

	if (0 && widget->allocation.width < ginfo->max_width &&
	    widget->allocation.height < ginfo->max_height)
		return TRUE;

	old_w = ginfo->max_width;
	old_h = ginfo->max_height;

	if (widget->allocation.width > ginfo->max_width)
		ginfo->max_width = widget->allocation.width;

	if (widget->allocation.height > ginfo->max_height)
		ginfo->max_height = widget->allocation.height;

	old_pix = ginfo->curr_pixmap;

	ginfo->curr_pixmap = gdk_pixmap_new(widget->window,
					    ginfo->max_width,
					    ginfo->max_height,
					    -1);

	gdk_draw_rectangle(ginfo->curr_pixmap,
			   widget->style->white_gc,
			   TRUE,
			   0, 0,
			   widget->allocation.width,
			   widget->allocation.height);

	draw_info(ginfo, old_w, old_h,
		  widget->allocation.width,
		  widget->allocation.height);

	if (old_pix) {
#if 0
		gdk_draw_drawable(ginfo->curr_pixmap,
				  ginfo->draw->style->fg_gc[GTK_WIDGET_STATE(ginfo->draw)],
				  old_pix,
				  0, 0, 0, 0,
				  old_w, old_h);
#endif

		g_object_unref(old_pix);
	}

	
	return TRUE;
}

static gboolean
destroy_event(GtkWidget *widget, gpointer data)
{
	struct graph_info *ginfo = data;

	if (ginfo->test)
		printf("test = %s\n", ginfo->test);

	return TRUE;
}


static GtkWidget *
create_drawing_area(struct tracecmd_input *handle)
{
	struct graph_info *ginfo;
	unsigned long sec, usec;
	gint cpu;

	ginfo = g_new0(typeof(*ginfo), 1);
	g_assert(ginfo != NULL);
	ginfo->test = "hello!";

	ginfo->handle = handle;
	ginfo->pevent = tracecmd_get_pevent(handle);
	ginfo->cpus = tracecmd_cpus(handle);

	ginfo->start_time = -1ULL;
	ginfo->end_time = 0;

	for (cpu = 0; cpu < ginfo->cpus; cpu++) {
		struct record *record;

		record = tracecmd_read_cpu_first(handle, cpu);
		if (!record)
			continue;

		if (record->ts < ginfo->start_time)
			ginfo->start_time = record->ts;

		record = tracecmd_read_cpu_last(handle, cpu);

		if (record->ts > ginfo->end_time)
			ginfo->end_time = record->ts;
	}

	convert_nano(ginfo->start_time, &sec, &usec);
	printf("start=%lu.%06lu ", sec, usec);

	convert_nano(ginfo->end_time, &sec, &usec);
	printf("end=%lu.%06lu\n", sec, usec);

	ginfo->view_start_time = ginfo->start_time;
	ginfo->view_end_time = ginfo->end_time;

	ginfo->draw = gtk_drawing_area_new();

	gtk_signal_connect(GTK_OBJECT(ginfo->draw), "expose_event",
			   (GtkSignalFunc) expose_event, ginfo);
	gtk_signal_connect(GTK_OBJECT(ginfo->draw), "button_press_event",
			   (GtkSignalFunc) button_press_event, ginfo);
	gtk_signal_connect(GTK_OBJECT(ginfo->draw), "configure_event",
			   (GtkSignalFunc) configure_event, ginfo);
	gtk_signal_connect(GTK_OBJECT(ginfo->draw), "motion_notify_event",
			   (GtkSignalFunc) motion_notify_event, ginfo);
	gtk_signal_connect(GTK_OBJECT(ginfo->draw), "button_release_event",
			   (GtkSignalFunc) button_release_event, ginfo);
	gtk_signal_connect(GTK_OBJECT(ginfo->draw), "destroy",
			   (GtkSignalFunc) destroy_event, ginfo);

	gtk_widget_set_events(ginfo->draw, GDK_EXPOSURE_MASK
			      | GDK_LEAVE_NOTIFY_MASK
			      | GDK_BUTTON_PRESS_MASK
			      | GDK_BUTTON_RELEASE_MASK
			      | GDK_POINTER_MOTION_MASK
			      | GDK_POINTER_MOTION_HINT_MASK);


	return ginfo->draw;
}

/* Callback for the clicked signal of the Exit button */
static void
exit_clicked (GtkWidget *widget, gpointer data)
{
	gtk_widget_destroy (GTK_WIDGET (data)); /* the user data points to the main window */
	gtk_main_quit ();
}

/* Callback for the delete_event signal of the main application window */
static gint
delete_event (GtkWidget *widget, GdkEvent *event, gpointer data)
{
	gtk_widget_destroy (widget); /* destroy the main window */
	gtk_main_quit ();
	return TRUE;
}

void trace_graph(int argc, char **argv)
{
	struct tracecmd_input *handle;
	GtkWidget *window;
	GtkWidget *vbox;
	GtkWidget *hbox;
	GtkWidget *menu_bar;
	GtkWidget *menu;
	GtkWidget *menu_item;
	GtkWidget *sub_item;
	GtkWidget *scrollwin;
	GtkWidget *draw;

	handle = tracecmd_open(input_file);

	if (!handle)
		die("error reading header");

	if (tracecmd_read_headers(handle) < 0)
		return;

	if (tracecmd_init_data(handle) < 0)
		die("failed to init data");

	gnome_init("trace-cmd", version, argc, argv);

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


	/* --- Top Level Hbox --- */

	hbox = gtk_hbox_new(FALSE, 0);
	gtk_box_pack_start(GTK_BOX(vbox), hbox, TRUE, TRUE, 0);
	gtk_widget_show(hbox);

	/* --- Scroll Window --- */
	scrollwin = gtk_scrolled_window_new(NULL, NULL);
	gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scrollwin),
				       GTK_POLICY_AUTOMATIC,
				       GTK_POLICY_AUTOMATIC);
	gtk_box_pack_start(GTK_BOX (hbox), scrollwin, TRUE, TRUE, 0);
	gtk_widget_show(scrollwin);

	/* --- Set up Drawing --- */

	draw = create_drawing_area(handle);

	gtk_scrolled_window_add_with_viewport(GTK_SCROLLED_WINDOW(scrollwin),
					      draw);
	gtk_widget_show(draw);


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
