#include "uapi.h"

#include <stdlib.h>

int uapi_start(wg_device_t *dev)
{
    (void)dev;
    return 0;
}

void uapi_stop(wg_device_t *dev)
{
    (void)dev;
}

int uapi_set_config(wg_device_t *dev, const char *settings)
{
    (void)dev;
    (void)settings;
    return -1;
}

char *uapi_get_config(wg_device_t *dev)
{
    (void)dev;
    return NULL;
}

