#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "parse-events.h"

int PEVENT_PLUGIN_LOADER(void)
{
	printf("HELLO WORLD!!!\n");
	return 0;
}
