include $(src)/scripts/utils.mk

TRACE_VIEW_OBJS =
TRACE_VIEW_OBJS += $(obj)/kernel-shark/trace-view.o
TRACE_VIEW_OBJS += $(obj)/kernel-shark/trace-view-store.o

ifdef BUILD_PYTHON_WORKS
PYTHON_SO_INSTALL := ctracecmd.install
PYTHON_PY_PROGS := event-viewer.install
PYTHON_PY_LIBS := tracecmd.install tracecmdgui.install
endif

ctracecmd.so: ctracecmd.i $(LIBTRACECMD_STATIC)
	swig -Wall -python -noproxy -I$(src)/include/traceevent -I$(src)/include/trace-cmd ctracecmd.i
	$(CC) -fpic -c $(CPPFLAGS) $(CFLAGS) $(PYTHON_INCLUDES)  ctracecmd_wrap.c
	$(CC) --shared $(LIBTRACECMD_STATIC) $(LDFLAGS) ctracecmd_wrap.o -o ctracecmd.so $(TRACE_LIBS)

ctracecmdgui.so: ctracecmdgui.i $(LIBTRACECMD_STATIC) $(TRACE_VIEW_OBJS)
	swig -Wall -python -noproxy -I$(src)/kernel-shark/include ctracecmdgui.i
	$(CC) -fpic -c  $(CPPFLAGS) $(CFLAGS) $(INCLUDES) $(PYTHON_INCLUDES) $(PYGTK_CFLAGS) ctracecmdgui_wrap.c
	$(CC) --shared $(TRACE_VIEW_OBJS) $(LIBTRACECMD_STATIC) $(LDFLAGS) $(LIBS) $(CONFIG_LIBS) ctracecmdgui_wrap.o -o ctracecmdgui.so $(TRACE_LIBS)


$(PYTHON_SO_INSTALL): %.install : %.so force
	$(Q)$(call do_install_data,$<,$(python_dir_SQ))

$(PYTHON_PY_PROGS): %.install : %.py force
	$(Q)$(call do_install,$<,$(python_dir_SQ))

$(PYTHON_PY_LIBS): %.install : %.py force
	$(Q)$(call do_install_data,$<,$(python_dir_SQ))

install_python: $(PYTHON_SO_INSTALL) $(PYTHON_PY_PROGS) $(PYTHON_PY_LIBS)


clean:
	$(RM) *.a *.so *.o .*.d ctracecmd_wrap.* ctracecmdgui_wrap.*

force:
.PHONY: clean force
