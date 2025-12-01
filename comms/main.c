#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/wait.h>
#include <pthread.h>

#include "../common.h"
#include "../nt_log.h"
#include "nt_comms.h"
#include "comms.h"

const char	syslog_app_name[] = "nt_base";

/* 这些全局变量在 nt_base 原工程中也会用到，这里简单给一个值即可 */
const char *progname = "nt_comms_test";          /* common.c 里有 extern progname */
pthread_t   tid;                                 /* common.c 里有 extern pthread_t tid */
char       *CONFIG_PID_FILE = "/tmp/nt_comms_test.pid";

/* 测试用的监听配置 */
const char *nt_config_listen_ip         = "127.0.0.1";
int         nt_config_listen_port       = 10051;
int         nt_config_timeout           = 5;    /* 秒 */
int         config_tcp_max_backlog_size = 10;

/* 简单的测试用例包装宏 */
#define TEST_CASE(name)                                  \
    do {                                                 \
        int __rc = (name)();                             \
        printf("[TEST] %-30s : %s\n",                    \
               #name, (__rc == SUCCEED) ? "OK" : "FAIL");\
        if (__rc != SUCCEED)                             \
            return EXIT_FAILURE;                         \
    } while (0)

/*======================================================================
 * 1. 只测试 nt_tcp_listen 是否能成功监听
 *====================================================================*/
static int test_nt_tcp_listen_only(void)
{
    nt_socket_t listen_sock;
    memset(&listen_sock, 0, sizeof(listen_sock));

    /* 这里就是你要求实现的那段代码 */
    if (FAIL == nt_tcp_listen(&listen_sock,
                              nt_config_listen_ip,
                              (unsigned short)nt_config_listen_port,
                              nt_config_timeout,
                              config_tcp_max_backlog_size))
    {
        nt_log(LOG_LEVEL_CRIT, "listener failed: %s", nt_socket_strerror());
        return FAIL;
    }

    nt_log(LOG_LEVEL_DEBUG, "listen OK on %s:%d",
           nt_config_listen_ip, nt_config_listen_port);

    nt_tcp_unlisten(&listen_sock);
    return SUCCEED;
}

/*======================================================================
 * 2. 子进程：客户端，测试 nt_tcp_connect / nt_tcp_write / nt_tcp_read
 *====================================================================*/
static int client_process(void)
{
    nt_socket_t  cli_sock;
    short        ev   = 0;
    const char  *msg  = "hello from client";
    char         buf[256];
    ssize_t      n;

    memset(&cli_sock, 0, sizeof(cli_sock));

    if (FAIL == nt_tcp_connect(&cli_sock,
                               NULL,                         /* source_ip */
                               nt_config_listen_ip,
                               (unsigned short)nt_config_listen_port,
                               nt_config_timeout,
                               NT_TCP_SEC_UNENCRYPTED,       /* 明文连接 */
                               NULL, NULL))
    {
        nt_log(LOG_LEVEL_CRIT, "client nt_tcp_connect failed: %s",
               nt_socket_strerror());
        return FAIL;
    }

    /* 写数据 */
    n = nt_tcp_write(&cli_sock, msg, strlen(msg), &ev);
    if (n <= 0)
    {
        nt_log(LOG_LEVEL_CRIT, "client nt_tcp_write failed: %s",
               nt_socket_strerror());
        nt_tcp_close(&cli_sock);
        return FAIL;
    }

    /* 读取服务器回显 */
    memset(buf, 0, sizeof(buf));
    n = nt_tcp_read(&cli_sock, buf, sizeof(buf) - 1, &ev);
    if (n <= 0)
    {
        nt_log(LOG_LEVEL_CRIT, "client nt_tcp_read failed: %s",
               nt_socket_strerror());
        nt_tcp_close(&cli_sock);
        return FAIL;
    }

    printf("[CLIENT] recv: %s\n", buf);

    nt_tcp_close(&cli_sock);
    return SUCCEED;
}

/*======================================================================
 * 3. 父进程：服务器端，测试
 *    nt_tcp_listen / nt_tcp_accept / nt_tcp_read / nt_tcp_write / nt_tcp_unaccept
 *====================================================================*/
static int server_process(void)
{
    nt_socket_t listen_sock;
    short       ev   = 0;
    char        buf[256];
    ssize_t     n;
    int         ret  = FAIL;

    memset(&listen_sock, 0, sizeof(listen_sock));

    if (FAIL == nt_tcp_listen(&listen_sock,
                              nt_config_listen_ip,
                              (unsigned short)nt_config_listen_port,
                              nt_config_timeout,
                              config_tcp_max_backlog_size))
    {
        nt_log(LOG_LEVEL_CRIT, "listener failed: %s", nt_socket_strerror());
        return FAIL;
    }

    nt_log(LOG_LEVEL_DEBUG, "server listening on %s:%d",
           nt_config_listen_ip, nt_config_listen_port);

    /* 等待客户端连接：只允许明文 NT_TCP_SEC_UNENCRYPTED */
    if (FAIL == nt_tcp_accept(&listen_sock,
                              NT_TCP_SEC_UNENCRYPTED, /* tls_accept */
                              nt_config_timeout,      /* poll_timeout 秒 */
                              NULL,                   /* tls_listen */
                              NULL))                  /* unencrypted_allowed_ip */
    {
        nt_log(LOG_LEVEL_CRIT, "nt_tcp_accept failed: %s",
               nt_socket_strerror());
        goto out;
    }

    /* 读客户端发来的数据 */
    memset(buf, 0, sizeof(buf));
    n = nt_tcp_read(&listen_sock, buf, sizeof(buf) - 1, &ev);
    if (n <= 0)
    {
        nt_log(LOG_LEVEL_CRIT, "server nt_tcp_read failed: %s",
               nt_socket_strerror());
        goto out;
    }

    printf("[SERVER] recv: %s\n", buf);

    /* 回显一条消息，测试 server 端的 nt_tcp_write */
    {
        const char *reply = "hello from server";
        n = nt_tcp_write(&listen_sock, reply, strlen(reply), &ev);
        if (n <= 0)
        {
            nt_log(LOG_LEVEL_CRIT, "server nt_tcp_write failed: %s",
                   nt_socket_strerror());
            goto out;
        }
    }

    ret = SUCCEED;

out:
    nt_tcp_unaccept(&listen_sock);   /* 关闭已接受连接，恢复为监听状态 */
    nt_tcp_unlisten(&listen_sock);   /* 关闭监听 socket */
    return ret;
}

/*======================================================================
 * 4. 综合测试：fork 出客户端进程，父进程作为服务器
 *====================================================================*/
static int test_nt_tcp_read_write(void)
{
    pid_t pid = fork();

    if (pid < 0)
    {
        perror("fork");
        return FAIL;
    }
    else if (pid == 0)
    {
        /* 子进程：sleep 一下，保证服务端先 listen 成功 */
        sleep(1);
        int rc = client_process();
        _exit(rc == SUCCEED ? 0 : 1);
    }
    else
    {
        int   status;
        int   svr_rc = server_process();
        pid_t w = waitpid(pid, &status, 0);

        if (w == -1)
        {
            perror("waitpid");
            return FAIL;
        }

        int cli_rc = (WIFEXITED(status) && WEXITSTATUS(status) == 0)
                       ? SUCCEED : FAIL;

        return (svr_rc == SUCCEED && cli_rc == SUCCEED)
                 ? SUCCEED : FAIL;
    }
}

/*======================================================================
 * main：顺序执行各个接口的简单测试
 *====================================================================*/
int main(int argc, char **argv)
{
    (void)argc;
    (void)argv;

    printf("=== nt_comms 接口简单测试 ===\n");

    TEST_CASE(test_nt_tcp_listen_only);
    TEST_CASE(test_nt_tcp_read_write);

    printf("=== 所有测试通过 ===\n");
    return EXIT_SUCCESS;
}

