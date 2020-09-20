#include <dfs_posix.h>
#include <sys/socket.h>
#include <sys/select.h>
#include "ftp_session.h"
#include "ftp_session_cmd.h"

#define MAX_CLIENT_NUM      10
#define FTP_USER            "rtt"
#define FTP_PASSWORD        "demo"
#define FTP_WELCOME_MSG		"220 -= welcome on RT-Thread FTP server =-\r\n"

static rt_slist_t session_header = RT_SLIST_OBJECT_INIT(session_header);

static int ftp_session_get_num(void)
{
    int num = 0;

    rt_base_t level = rt_hw_interrupt_disable();
    num = rt_slist_len(&session_header);
    rt_hw_interrupt_enable(level);

    return num;
}

static int ftp_session_delete(struct ftp_session * session)
{
    rt_base_t level = rt_hw_interrupt_disable();
    rt_slist_remove(&session_header, &(session->slist));
    rt_hw_interrupt_enable(level);

    close(session->fd);
    if(session->port_pasv_fd >= 0)
        close(session->port_pasv_fd);
    rt_free(session);

    return RT_EOK;
}

static int ftp_session_read(struct ftp_session *session, uint8_t *buf, int bufsz, int timeout)
{
    int bytes = 0;
    int rc = 0;
    
    if(bufsz <= 0)
        return bufsz;

    while(bytes < bufsz)
    {
        rc = recv(session->fd, &buf[bytes], (size_t)(bufsz - bytes), MSG_DONTWAIT);
        if(rc <= 0)
            return -1;

        bytes += rc;
        if(bytes >= bufsz)
            break;
        
        if(timeout > 0)
        {
            fd_set readset, exceptset;
            struct timeval interval;

            interval.tv_sec = timeout / 1000;
            interval.tv_usec = (timeout % 1000) * 1000;

            FD_ZERO(&readset);
            FD_ZERO(&exceptset);
            FD_SET(session->fd, &readset);
            FD_SET(session->fd, &exceptset);

            rc = select(session->fd + 1, &readset, RT_NULL, &exceptset, &interval);
            if(rc < 0)
                return -1;
            if(rc == 0)
                break;
            if(FD_ISSET(session->fd, &exceptset))
                return -1;
        }
        else
            break;
    }

    return bytes;
}

static int ftp_session_process(struct ftp_session * session, char *cmd_buf)
{
    int result = RT_EOK;

    /* remove \r\n */
    char *ptr = cmd_buf;
    while (*ptr)
	{
		if ((*ptr == '\r') || (*ptr == '\n'))
            *ptr = 0;
		ptr ++;
	}

    int tick_timeout = 3;
    char *cmd = cmd_buf;
    char *cmd_param = strchr(cmd, ' ');
    if(cmd_param)
    {
        *cmd_param = '\0';
        cmd_param++;
    }

    switch(session->state)
    {
        case FTP_SESSION_STATE_USER:
        {
            if(strstr(cmd, "USER") != cmd)
            {
                char *reply = "502 Not Implemented.\r\n";
                send(session->fd, reply, strlen(reply), 0);
                break;
            }

            if(strcmp(cmd_param, "anonymous") == 0)
            {
                session->is_anonymous = 1;
                char *reply = "331 anonymous login OK send e-mail address for password.\r\n";
                send(session->fd, reply, strlen(reply), 0);
                session->state = FTP_SESSION_STATE_PASSWD;
                break;
            }

            if(strcmp(cmd_param, FTP_USER) == 0)
            {
                session->is_anonymous = 0;
                char *reply = "331 Password required.\r\n";
                send(session->fd, reply, strlen(reply), 0);
                session->state = FTP_SESSION_STATE_PASSWD;
                break;
            }

            char *reply = "530 Login incorrect. Bye.\r\n";
            send(session->fd, reply, strlen(reply), 0);
            result = -RT_ERROR;
        }
        break;

        case FTP_SESSION_STATE_PASSWD:
        {
            if(strstr(cmd, "PASS") != cmd)
            {
                char *reply = "502 Not Implemented.\r\n";
                send(session->fd, reply, strlen(reply), 0);
                break;
            }

            if(session->is_anonymous || (strcmp(cmd_param, FTP_PASSWORD) == 0))
            {
                char *reply = "230 User logged in\r\n";
                send(session->fd, reply, strlen(reply), 0);
                rt_memset(session->currentdir, 0, sizeof(session->currentdir));
                session->currentdir[0] = '/';
                session->state = FTP_SESSION_STATE_PROCESS;
                break;
            }

            char *reply = "530 Login incorrect. Bye.\r\n";
            send(session->fd, reply, strlen(reply), 0);
            result = -RT_ERROR;
        }
        break;

        case FTP_SESSION_STATE_PROCESS:
        {
            int rc = ftp_session_cmd_process(session, cmd, cmd_param);
            if(rc != RT_EOK)
            {
                result = -RT_ERROR;
                break;
            }
        }
        break;

        default:
            result = -RT_ERROR;
        break;
    }

    session->tick_timeout = rt_tick_get() + rt_tick_from_millisecond(tick_timeout * 1000);

    return result;
}

static void ftp_client_entry(void *parameter)
{
    struct ftp_session *session = parameter;
    int option = 1;
    int rc = setsockopt(session->fd, IPPROTO_TCP, TCP_NODELAY, (const void *)&option, sizeof(int));
    if(rc < 0)
        goto _exit;
    
    uint32_t loption = 1;
    ioctlsocket(session->fd, FIONBIO, &loption);

    session->port_pasv_fd = -1;
    session->is_anonymous = 0;
    session->offset = 0;
    session->state = FTP_SESSION_STATE_USER;
    session->tick_timeout = rt_tick_get() + rt_tick_from_millisecond(3000);

    char cmd_buf[1024];

    // select使用
    fd_set readset, exceptset;   
    // select超时时间
    struct timeval select_timeout;
    select_timeout.tv_sec = 1;
    select_timeout.tv_usec = 0;

    send(session->fd, FTP_WELCOME_MSG, strlen(FTP_WELCOME_MSG), 0);

    while(1)
    {
        FD_ZERO(&readset);
        FD_ZERO(&exceptset);

        FD_SET(session->fd, &readset);
        FD_SET(session->fd, &exceptset);

        rc = select(session->fd + 1, &readset, RT_NULL, &exceptset, &select_timeout);
        if(rc < 0)
            break;
        if(rc > 0)
        {
            if(FD_ISSET(session->fd, &exceptset))
                break;
            if(FD_ISSET(session->fd, &readset))
            {
                int cmd_len = ftp_session_read(session, (uint8_t *)cmd_buf, sizeof(cmd_buf) - 1, 30);
                if(cmd_len <= 0)
                    break;
                cmd_buf[cmd_len] = '\0';
                if(ftp_session_process(session, cmd_buf) != RT_EOK)
                    break;
            }
        }

        if((rt_tick_get() - session->tick_timeout) < (RT_TICK_MAX / 2))
            break;
    }

_exit:
    ftp_session_delete(session);
}

int ftp_session_create(int fd, struct sockaddr_in *addr, socklen_t addr_len)
{
    if(fd < 0)
        return -RT_ERROR;
    
    if(ftp_session_get_num() >= MAX_CLIENT_NUM)
        return -RT_ERROR;
    
    struct ftp_session *session = rt_malloc(sizeof(struct ftp_session));
    if(session == RT_NULL)
        return -RT_ERROR;
    rt_memset(session, 0, sizeof(struct ftp_session));
    session->fd = fd;
    rt_memcpy(&(session->remote), addr, addr_len);
    rt_slist_init(&(session->slist));
    rt_base_t level = rt_hw_interrupt_disable();
    rt_slist_append(&session_header, &(session->slist));
    rt_hw_interrupt_enable(level);

    rt_thread_t tid = rt_thread_create("ftpc", ftp_client_entry, session, 4096, 27, 100);
    RT_ASSERT(tid != RT_NULL);
    rt_thread_startup(tid);

    return RT_EOK;
}
