#pragma once

#include_next <time.h>

#if defined(_WIN32) && !defined(_POSIX_THREAD_SAFE_FUNCTIONS)
static inline struct tm *localtime_r(const time_t *timep, struct tm *result)
{
    return localtime_s(result, timep) == 0 ? result : NULL;
}
#endif
