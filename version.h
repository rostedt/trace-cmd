#ifndef _VERSION_H
#define _VERSION_H

#define VERSION(a, b) (((a) << 8) + (b))

#ifdef BUILDGUI
#include "ks_version.h"
#else
#include "tc_version.h"
#endif

#define _STR(x)	#x
#define STR(x)	_STR(x)

#define FILE_VERSION_STRING STR(FILE_VERSION)

#endif /* _VERSION_H */
