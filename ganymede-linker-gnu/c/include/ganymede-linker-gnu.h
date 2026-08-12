#ifndef GANYMEDE_LINKER_GNU_H
#define GANYMEDE_LINKER_GNU_H

#if __SIZEOF_POINTER__ == 4
#define r_debug r_debug_32
#define r_debug_extended r_debug_extended_32
#define link_map link_map_32
#elif __SIZEOF_POINTER__ == 8
#define r_debug r_debug_64
#define r_debug_extended r_debug_extended_64
#define link_map link_map_64
#else
#error Unsupported GNU linker pointer width
#endif

#include <link.h>

#undef r_debug
#undef r_debug_extended
#undef link_map

#endif
