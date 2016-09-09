#ifndef _TRACE_MSG_H_
#define _TRACE_MSG_H_

#include <stdbool.h>

#define UDP_MAX_PACKET	(65536 - 20)
#define V2_MAGIC	"677768\0"
#define V2_CPU		"-1V2"

#define V1_PROTOCOL	1
#define V2_PROTOCOL	2

extern unsigned int page_size;

void plog(const char *fmt, ...);
void pdie(const char *fmt, ...);

#endif /* _TRACE_MSG_H_ */
