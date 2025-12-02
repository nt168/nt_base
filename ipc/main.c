
#include "nt_ipcservice.h"

int main(void)
{
    char *error = NULL;
    if (SUCCEED != nt_ipc_service_init_env("/tmp", &error))
    {
        fprintf(stderr, "init failed: %s\n", error ? error : "unknown");
        free(error);
        return 1;
    }

    printf("IPC root path: %s\n", "/tmp");
    nt_ipc_service_free_env();
    return 0;
}