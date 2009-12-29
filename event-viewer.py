#!/usr/bin/env python

from gobject import *
import gtk
from tracecmd import *

app = None
data_func_cnt = 0

# In a "real" app these width should be determined at runtime testing max length
# strings in the current font.
TS_COL_W    = 150
CPU_COL_W   = 35
EVENT_COL_W = 150
PID_COL_W   = 75
COMM_COL_W  = 250

class EventStore(gtk.ListStore):
    def __init__(self, trace):
        gtk.ListStore.__init__(self, gobject.TYPE_PYOBJECT)
        self.trace = trace
        for cpu in range(0, trace.cpus):
            ev = trace.read_event(cpu)
            while ev:
                # store the record offset into the trace file
                self.append([record_offset_get(ev.rec)])
                ev = trace.read_event(cpu)
        print "Loaded %d events across %d cpus" % (len(self), trace.cpus)

    def get_event(self, iter):
        offset = self.get_value(iter, 0)
        return self.trace.read_event_at(offset)


class EventView(gtk.TreeView):
    def __init__(self, model):
        gtk.TreeView.__init__(self, model)
        self.set_fixed_height_mode(True)

        ts_col = gtk.TreeViewColumn("Time (s)")
        ts_col.set_sizing(gtk.TREE_VIEW_COLUMN_FIXED)
        ts_col.set_fixed_width(TS_COL_W)
        ts_cell = gtk.CellRendererText()
        ts_col.pack_start(ts_cell, False)
        ts_col.set_cell_data_func(ts_cell, self.data_func, "ts")
        self.append_column(ts_col)

        cpu_col = gtk.TreeViewColumn("CPU")
        cpu_col.set_sizing(gtk.TREE_VIEW_COLUMN_FIXED)
        cpu_col.set_fixed_width(CPU_COL_W)
        cpu_cell = gtk.CellRendererText()
        cpu_col.pack_start(cpu_cell, False)
        cpu_col.set_cell_data_func(cpu_cell, self.data_func, "cpu")
        self.append_column(cpu_col)

        event_col = gtk.TreeViewColumn("Event")
        event_col.set_sizing(gtk.TREE_VIEW_COLUMN_FIXED)
        event_col.set_fixed_width(EVENT_COL_W)
        event_cell = gtk.CellRendererText()
        event_col.pack_start(event_cell, False)
        event_col.set_cell_data_func(event_cell, self.data_func, "event")
        self.append_column(event_col)

        pid_col = gtk.TreeViewColumn("PID")
        pid_col.set_sizing(gtk.TREE_VIEW_COLUMN_FIXED)
        pid_col.set_fixed_width(PID_COL_W)
        pid_cell = gtk.CellRendererText()
        pid_col.pack_start(pid_cell, False)
        pid_col.set_cell_data_func(pid_cell, self.data_func, "pid")
        self.append_column(pid_col)

        comm_col = gtk.TreeViewColumn("Comm")
        comm_col.set_sizing(gtk.TREE_VIEW_COLUMN_FIXED)
        comm_col.set_fixed_width(COMM_COL_W)
        comm_cell = gtk.CellRendererText()
        comm_col.pack_start(comm_cell, False)
        comm_col.set_cell_data_func(comm_cell, self.data_func, "comm")
        self.append_column(comm_col)

    def data_func(self, col, cell, model, iter, data):
        global app, data_func_cnt

        ev = model.get_event(iter)
        if not ev:
            return False
        if data == "ts":
            cell.set_property("markup", "%d.%d" % (ev.ts/1000000000,
                                                   ev.ts%1000000000))
            data_func_cnt = data_func_cnt + 1
            if app:
                app.inc_data_func()
            return True
        if data == "cpu":
            cell.set_property("markup", ev.cpu)
            return True
        if data == "event":
            cell.set_property("markup", ev.name)
            return True
        if data == "pid":
            cell.set_property("markup", ev.pid)
            return True
        if data == "comm":
            cell.set_property("markup", ev.comm)
            return True

        return False


class EventViewerApp(gtk.Window):
    def __init__(self, trace):
        gtk.Window.__init__(self)

        self.set_size_request(650, 400)
        self.set_position(gtk.WIN_POS_CENTER)

        self.connect("destroy", gtk.main_quit)
        self.set_title("Event Viewer")


        es = EventStore(trace)
        view = EventView(es)

        sw = gtk.ScrolledWindow()
        sw.set_policy(gtk.POLICY_NEVER, gtk.POLICY_ALWAYS)
        sw.add(view)

        # track how often the treeview data_func is called
        self.data_func_label = gtk.Label("0")
        hbox = gtk.HBox()
        hbox.pack_start(gtk.Label("TS Data Func Calls:"), False, False)
        hbox.pack_start(self.data_func_label, False, False)

        vbox = gtk.VBox()
        vbox.pack_start(hbox, False)
        vbox.pack_end(sw)

        self.add(vbox)
        self.show_all()

    def inc_data_func(self):
        global data_func_cnt
        self.data_func_label.set_text(str(data_func_cnt))


if __name__ == "__main__":
    trace = Trace("trace.dat")
    app = EventViewerApp(trace)
    gtk.main()
