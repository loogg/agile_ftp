#include "init_module.h"
#include "plugins.h"
#include <dfs_posix.h>
#include <sys/socket.h>
#include <sys/select.h>
#include "ftp_session.h"

#define DBG_TAG "ftp"
#define DBG_LVL DBG_INFO
#include <rtdbg.h>

#define DEFAULT_PORT        21

static struct plugins_module ftp_plugin = {
	.name = "ftp",
	.version = "v1.0.0",
	.author = "malongwei"
};

static struct init_module ftp_init_module;

static void ftp_entry(void *parameter)
{
    ftp_plugin.state = PLUGINS_STATE_RUNNING;

    int server_fd = -1;
    int enable = 1;
    uint32_t loption = 1;
    struct sockaddr_in addr;
    socklen_t addrlen;

    // select使用
    fd_set readset, exceptset;
    // select超时时间
    struct timeval select_timeout;
    select_timeout.tv_sec = 1;
    select_timeout.tv_usec = 0;

    rt_thread_mdelay(5000);

_ftp_start:
    server_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if(server_fd < 0)
        goto _ftp_restart;
    
    if(setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, (const void *)&enable, sizeof(enable)) < 0)
        goto _ftp_restart;
    
    rt_memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(DEFAULT_PORT);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    if(bind(server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
        goto _ftp_restart;
    
    if(listen(server_fd, 1) < 0)
        goto _ftp_restart;
    
    ioctlsocket(server_fd, FIONBIO, &loption);

    while(1)
    {
        FD_ZERO(&readset);
        FD_ZERO(&exceptset);

        FD_SET(server_fd, &readset);
        FD_SET(server_fd, &exceptset);

        int rc = select(server_fd + 1, &readset, RT_NULL, &exceptset, &select_timeout);
        if(rc < 0)
            break;
        if(rc > 0)
        {
            if (FD_ISSET(server_fd, &exceptset))
                break;
            if (FD_ISSET(server_fd, &readset))
            {
                addrlen = sizeof(struct sockaddr_in);
                int client_fd = accept(server_fd, (struct sockaddr *)&addr, &addrlen);
                if(client_fd < 0)
                    break;
                if(ftp_session_create(client_fd, &addr, addrlen) != RT_EOK)
                    close(client_fd);
            }
        }
    }

_ftp_restart:
    if(server_fd >= 0)
    {
        close(server_fd);
        server_fd = -1;
    }

    rt_thread_mdelay(10000);
    goto _ftp_start;
}

static int ftp_init(void)
{
    rt_thread_t tid = rt_thread_create("ftp", ftp_entry, RT_NULL, 2048, 27, 100);
    RT_ASSERT(tid != RT_NULL);
    rt_thread_startup(tid);

    return RT_EOK;
}

int fregister(const char *path, void *dlmodule, uint8_t is_sys)
{
    plugins_register(&ftp_plugin, path, dlmodule, is_sys);

    ftp_init_module.init = ftp_init;
    init_module_app_register(&ftp_init_module);

    return RT_EOK;
}
