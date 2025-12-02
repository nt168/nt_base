#include "../common.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <sys/stat.h>
#include "../nt_log.h"
#include "nt_comms.h"

const char      syslog_app_name[] = "nt_base";
const char     *progname = "nt_client";
pthread_t       tid;
char           *CONFIG_PID_FILE = "/tmp/nt_client.pid";

static void usage(const char *program)
{
    fprintf(stderr, "Usage: %s [-a addr] [-p port] (-f file | -c content)\n", program);
    fprintf(stderr, "  -a, --address   Server address (default: 127.0.0.1)\n");
    fprintf(stderr, "  -p, --port      Server port (default: 8192)\n");
    fprintf(stderr, "  -f, --file      Read data from file to send\n");
    fprintf(stderr, "  -c, --content   Send the provided string directly\n");
    fprintf(stderr, "  -h, --help      Show this help message\n");
}

static char *read_file(const char *path, size_t *out_len)
{
    struct stat st;
    FILE       *fp   = NULL;
    char       *data = NULL;

    if (0 != stat(path, &st))
    {
        perror("stat");
        return NULL;
    }

    fp = fopen(path, "rb");
    if (NULL == fp)
    {
        perror("fopen");
        return NULL;
    }

    data = malloc((size_t)st.st_size);
    if (NULL == data)
    {
        perror("malloc");
        fclose(fp);
        return NULL;
    }

    if (st.st_size != (ssize_t)fread(data, 1, (size_t)st.st_size, fp))
    {
        perror("fread");
        free(data);
        data = NULL;
    }
    else
    {
        *out_len = (size_t)st.st_size;
    }

    fclose(fp);
    return data;
}

int main(int argc, char **argv)
{
    const char     *server_ip   = "127.0.0.1";
    unsigned short  server_port = 8192;
    const char     *file_path   = NULL;
    const char     *inline_data = NULL;
    char           *payload     = NULL;
    size_t          payload_len = 0;
    int             opt;

    static const struct option long_opts[] = {
        {"address", required_argument, NULL, 'a'},
        {"port",    required_argument, NULL, 'p'},
        {"file",    required_argument, NULL, 'f'},
        {"content", required_argument, NULL, 'c'},
        {"help",    no_argument,       NULL, 'h'},
        {0, 0, 0, 0}
    };

    while (-1 != (opt = getopt_long(argc, argv, "a:p:f:c:h", long_opts, NULL)))
    {
        switch (opt)
        {
            case 'a':
                server_ip = optarg;
                break;
            case 'p':
            {
                long port = strtol(optarg, NULL, 10);
                if (port <= 0 || port > 65535)
                {
                    fprintf(stderr, "Invalid port: %s\n", optarg);
                    return EXIT_FAILURE;
                }
                server_port = (unsigned short)port;
                break;
            }
            case 'f':
                file_path = optarg;
                break;
            case 'c':
                inline_data = optarg;
                break;
            case 'h':
                usage(argv[0]);
                return EXIT_SUCCESS;
            default:
                usage(argv[0]);
                return EXIT_FAILURE;
        }
    }

    if ((NULL == file_path && NULL == inline_data) || (NULL != file_path && NULL != inline_data))
    {
        fprintf(stderr, "Either -f or -c must be provided (but not both).\n");
        usage(argv[0]);
        return EXIT_FAILURE;
    }

    if (NULL != file_path)
    {
        payload = read_file(file_path, &payload_len);
        if (NULL == payload)
            return EXIT_FAILURE;
    }
    else
    {
        payload = strdup(inline_data);
        if (NULL == payload)
        {
            perror("strdup");
            return EXIT_FAILURE;
        }
        payload_len = strlen(payload);
    }

    nt_socket_t sock;
    short       ev = 0;
    memset(&sock, 0, sizeof(sock));

    if (FAIL == nt_tcp_connect(&sock, NULL, server_ip, server_port, 5, NT_TCP_SEC_UNENCRYPTED, NULL, NULL))
    {
        nt_log(LOG_LEVEL_CRIT, "nt_tcp_connect failed: %s", nt_socket_strerror());
        free(payload);
        return EXIT_FAILURE;
    }

    if (payload_len != (size_t)nt_tcp_write(&sock, payload, payload_len, &ev))
    {
        nt_log(LOG_LEVEL_CRIT, "nt_tcp_write failed: %s", nt_socket_strerror());
        nt_tcp_close(&sock);
        free(payload);
        return EXIT_FAILURE;
    }

    printf("Sent %zu bytes to %s:%u\n", payload_len, server_ip, server_port);

    nt_tcp_close(&sock);
    free(payload);
    return EXIT_SUCCESS;
}
