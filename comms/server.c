#include "../common.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include "../nt_log.h"
#include "nt_comms.h"

const char      syslog_app_name[] = "nt_base";
const char     *progname = "nt_server";
pthread_t       tid;
char           *CONFIG_PID_FILE = "/tmp/nt_server.pid";

static void usage(const char *program)
{
    fprintf(stderr, "Usage: %s [-a addr] [-p port] [-f output_file]\n", program);
    fprintf(stderr, "  -a, --address   Listen address (default: 127.0.0.1)\n");
    fprintf(stderr, "  -p, --port      Listen port (default: 8192)\n");
    fprintf(stderr, "  -f, --file      Save received data to file instead of stdout\n");
    fprintf(stderr, "  -h, --help      Show this help message\n");
}

static int handle_client(nt_socket_t *sock, FILE *output)
{
    char    buffer[1024];
    ssize_t nread;

    while (0 < (nread = nt_tcp_read(sock, buffer, sizeof(buffer), NULL)))
    {
        if (NULL != output)
        {
            if ((size_t)nread != fwrite(buffer, 1, (size_t)nread, output))
            {
                perror("fwrite");
                return FAIL;
            }
            fflush(output);
        }
        else
        {
            fwrite(buffer, 1, (size_t)nread, stdout);
            fflush(stdout);
        }
    }

    if (0 > nread)
    {
        nt_log(LOG_LEVEL_CRIT, "nt_tcp_read failed: %s", nt_socket_strerror());
        return FAIL;
    }

    return SUCCEED;
}

int main(int argc, char **argv)
{
    const char     *listen_ip   = "127.0.0.1";
    unsigned short  listen_port = 8192;
    const char     *output_path = NULL;
    FILE           *output      = NULL;
    int             opt;

    static const struct option long_opts[] = {
        {"address", required_argument, NULL, 'a'},
        {"port",    required_argument, NULL, 'p'},
        {"file",    required_argument, NULL, 'f'},
        {"help",    no_argument,       NULL, 'h'},
        {0, 0, 0, 0}
    };

    while (-1 != (opt = getopt_long(argc, argv, "a:p:f:h", long_opts, NULL)))
    {
        switch (opt)
        {
            case 'a':
                listen_ip = optarg;
                break;
            case 'p':
            {
                long port = strtol(optarg, NULL, 10);
                if (port <= 0 || port > 65535)
                {
                    fprintf(stderr, "Invalid port: %s\n", optarg);
                    return EXIT_FAILURE;
                }
                listen_port = (unsigned short)port;
                break;
            }
            case 'f':
                output_path = optarg;
                break;
            case 'h':
                usage(argv[0]);
                return EXIT_SUCCESS;
            default:
                usage(argv[0]);
                return EXIT_FAILURE;
        }
    }

    if (NULL != output_path)
    {
        output = fopen(output_path, "wb");
        if (NULL == output)
        {
            perror("fopen");
            return EXIT_FAILURE;
        }
    }

    nt_socket_t listen_sock;
    memset(&listen_sock, 0, sizeof(listen_sock));

    if (FAIL == nt_tcp_listen(&listen_sock, listen_ip, listen_port, 5, 10))
    {
        nt_log(LOG_LEVEL_CRIT, "Failed to listen on %s:%u: %s", listen_ip, listen_port,
               nt_socket_strerror());
        if (NULL != output)
            fclose(output);
        return EXIT_FAILURE;
    }

    printf("Server listening on %s:%u\n", listen_ip, listen_port);

    for (;;)
    {
        if (FAIL == nt_tcp_accept(&listen_sock, NT_TCP_SEC_UNENCRYPTED, 5, NULL, NULL))
        {
            nt_log(LOG_LEVEL_CRIT, "nt_tcp_accept failed: %s", nt_socket_strerror());
            break;
        }

        if (FAIL == handle_client(&listen_sock, output))
        {
            nt_tcp_unaccept(&listen_sock);
            break;
        }

        nt_tcp_unaccept(&listen_sock);
    }

    if (NULL != output)
        fclose(output);

    nt_tcp_unlisten(&listen_sock);
    return EXIT_SUCCESS;
}
