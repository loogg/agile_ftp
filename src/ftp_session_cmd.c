#include <dfs_posix.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/select.h>
#include "ftp_session_cmd.h"

static int ftp_create_dir(const char *path)
{
    int result = RT_EOK;

    DIR *dir = opendir(path);
    if(dir == RT_NULL)
    {
        if(mkdir(path, 0x777) != 0)
            result = -RT_ERROR;
    }
    else
        closedir(dir);

    return result;
}

static char* ftp_normalize_path(char* fullpath)
{
    char *dst0, *dst, *src;

    src = fullpath;
    dst = fullpath;

    dst0 = dst;
    while (1)
    {
        char c = *src;

        if (c == '.')
        {
            if (!src[1]) src ++; /* '.' and ends */
            else if (src[1] == '/')
            {
                /* './' case */
                src += 2;

                while ((*src == '/') && (*src != '\0')) src ++;
                continue;
            }
            else if (src[1] == '.')
            {
                if (!src[2])
                {
                    /* '..' and ends case */
                    src += 2;
                    goto up_one;
                }
                else if (src[2] == '/')
                {
                    /* '../' case */
                    src += 3;

                    while ((*src == '/') && (*src != '\0')) src ++;
                    goto up_one;
                }
            }
        }

        /* copy up the next '/' and erase all '/' */
        while ((c = *src++) != '\0' && c != '/') *dst ++ = c;

        if (c == '/')
        {
            *dst ++ = '/';
            while (c == '/') c = *src++;

            src --;
        }
        else if (!c) break;

        continue;

up_one:
        dst --;
        if (dst < dst0) return RT_NULL;
        while (dst0 < dst && dst[-1] != '/') dst --;
    }

    *dst = '\0';

    /* remove '/' in the end of path if exist */
    dst --;
    if ((dst != fullpath) && (*dst == '/')) *dst = '\0';

    return fullpath;
}

static int port_cmd_fn(struct ftp_session *session, char *cmd, char *cmd_param)
{
    if (session->port_pasv_fd >= 0)
    {
        close(session->port_pasv_fd);
        session->port_pasv_fd = -1;
    }

    char *reply = RT_NULL;
    int portcom[6];
    char iptmp[100];
    int index = 0;
    char *ptr = cmd_param;
    while (ptr != RT_NULL)
    {
        if (*ptr == ',')
            ptr++;
        portcom[index] = atoi(ptr);
        if ((portcom[index] < 0) || (portcom[index] > 255))
            break;
        index++;
        if (index == 6)
            break;
        ptr = strchr(ptr, ',');
    }
    if (index < 6)
    {
        reply = "504 invalid parameter.\r\n";
        send(session->fd, reply, strlen(reply), 0);
        return RT_EOK;
    }

    snprintf(iptmp, sizeof(iptmp), "%d.%d.%d.%d", portcom[0], portcom[1], portcom[2], portcom[3]);

    int rc = -RT_ERROR;
    do
    {
        session->port_pasv_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (session->port_pasv_fd < 0)
            break;
        struct timeval tv;
        tv.tv_sec = 20;
        tv.tv_usec = 0;
        if (setsockopt(session->port_pasv_fd, SOL_SOCKET, SO_SNDTIMEO, (const void *)&tv, sizeof(struct timeval)) < 0)
            break;
        struct sockaddr_in addr;
        rt_memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(portcom[4] * 256 + portcom[5]);
        addr.sin_addr.s_addr = inet_addr(iptmp);
        if (connect(session->port_pasv_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
            break;

        rc = RT_EOK;
    } while (0);

    if (rc != RT_EOK)
    {
        reply = "425 Can't open data connection.\r\n";
        send(session->fd, reply, strlen(reply), 0);
        if (session->port_pasv_fd >= 0)
        {
            close(session->port_pasv_fd);
            session->port_pasv_fd = -1;
        }
        return RT_EOK;
    }

    reply = "200 Port Command Successful.\r\n";
    send(session->fd, reply, strlen(reply), 0);
    return RT_EOK;
}

static int pwd_cmd_fn(struct ftp_session *session, char *cmd, char *cmd_param)
{
    char *reply = rt_malloc(1024);
    if(reply == RT_NULL)
        return -RT_ERROR;

    snprintf(reply, 1024, "257 \"%s\" is current directory.\r\n", session->currentdir);
    send(session->fd, reply, strlen(reply), 0);
    rt_free(reply);
    return RT_EOK;
}

static int type_cmd_fn(struct ftp_session *session, char *cmd, char *cmd_param)
{
    // Ignore it
    char *reply = RT_NULL;
    if (strcmp(cmd_param, "I") == 0)
        reply = "200 Type set to binary.\r\n";
    else
        reply = "200 Type set to ascii.\r\n";

    send(session->fd, reply, strlen(reply), 0);
    return RT_EOK;
}

static int syst_cmd_fn(struct ftp_session *session, char *cmd, char *cmd_param)
{
    char *reply = "215 RT-Thread RTOS\r\n";
    send(session->fd, reply, strlen(reply), 0);
    return RT_EOK;
}

static int quit_cmd_fn(struct ftp_session *session, char *cmd, char *cmd_param)
{
    char *reply = "221 Bye!\r\n";
    send(session->fd, reply, strlen(reply), 0);

    return -RT_ERROR;
}

static int list_cmd_fn(struct ftp_session *session, char *cmd, char *cmd_param)
{
    char *reply = RT_NULL;
    if (session->port_pasv_fd < 0)
    {
        reply = "502 Not Implemented.\r\n";
        send(session->fd, reply, strlen(reply), 0);
        return RT_EOK;
    }

    DIR *dir = opendir(session->currentdir);
    if(dir == RT_NULL)
    {
        reply = rt_malloc(1024);
        if(reply == RT_NULL)
            return -RT_ERROR;

        snprintf(reply, 1024, "550 directory \"%s\" can't open.\r\n", session->currentdir);
        send(session->fd, reply, strlen(reply), 0);
        rt_free(reply);
        return RT_EOK;
    }

    reply = "150 Opening Binary mode connection for file list.\r\n";
    send(session->fd, reply, strlen(reply), 0);

    struct dirent *dirent = RT_NULL;
    char tmp[256];
    struct stat s;
    do
    {
        dirent = readdir(dir);
        if(dirent == RT_NULL)
            break;
        snprintf(tmp, sizeof(tmp), "%s/%s", session->currentdir, dirent->d_name);
        rt_memset(&s, 0, sizeof(struct stat));
        if(stat(tmp, &s) != 0)
            continue;
        if(S_ISDIR(s.st_mode))
            snprintf(tmp, sizeof(tmp), "drw-r--r-- 1 admin admin %d Jan 1 2020 %s\r\n", 0, dirent->d_name);
        else
            snprintf(tmp, sizeof(tmp), "-rw-r--r-- 1 admin admin %d Jan 1 2020 %s\r\n", s.st_size, dirent->d_name);
        send(session->port_pasv_fd, tmp, strlen(tmp), 0);
    }while(dirent != RT_NULL);

    closedir(dir);

    close(session->port_pasv_fd);
    session->port_pasv_fd = -1;

    reply = "226 Transfert Complete.\r\n";
    send(session->fd, reply, strlen(reply), 0);
    return RT_EOK;
}

static int nlist_cmd_fn(struct ftp_session *session, char *cmd, char *cmd_param)
{
    char *reply = RT_NULL;
    if (session->port_pasv_fd < 0)
    {
        reply = "502 Not Implemented.\r\n";
        send(session->fd, reply, strlen(reply), 0);
        return RT_EOK;
    }

    DIR *dir = opendir(session->currentdir);
    if (dir == RT_NULL)
    {
        reply = rt_malloc(1024);
        if(reply == RT_NULL)
            return -RT_ERROR;

        snprintf(reply, 1024, "550 directory \"%s\" can't open.\r\n", session->currentdir);
        send(session->fd, reply, strlen(reply), 0);
        rt_free(reply);
        return RT_EOK;
    }

    reply = "150 Opening Binary mode connection for file list.\r\n";
    send(session->fd, reply, strlen(reply), 0);

    struct dirent *dirent = RT_NULL;
    char tmp[256];
    do
    {
        dirent = readdir(dir);
        if (dirent == RT_NULL)
            break;
        snprintf(tmp, sizeof(tmp), "%s\r\n", dirent->d_name);
        send(session->port_pasv_fd, tmp, strlen(tmp), 0);
    } while (dirent != RT_NULL);

    closedir(dir);

    close(session->port_pasv_fd);
    session->port_pasv_fd = -1;

    reply = "226 Transfert Complete.\r\n";
    send(session->fd, reply, strlen(reply), 0);
    return RT_EOK;
}

static int build_full_path(char *buf, int bufsz, const char *path)
{
    if(path[0] == '/')
        snprintf(buf, bufsz, "%s", path);
    else
    {
        strcat(buf, "/");
        int remain_len = bufsz - strlen(buf) - 1;
        strncat(buf, path, remain_len);
    }

    if(ftp_normalize_path(buf) == RT_NULL)
        return -RT_ERROR;

    return RT_EOK;
}

static int cwd_cmd_fn(struct ftp_session *session, char *cmd, char *cmd_param)
{
    if(build_full_path(session->currentdir, sizeof(session->currentdir), cmd_param) != RT_EOK)
        return -RT_ERROR;

    char *reply = RT_NULL;
    DIR *dir = opendir(session->currentdir);
    if (dir == RT_NULL)
    {
        reply = rt_malloc(1024);
        if(reply == RT_NULL)
            return -RT_ERROR;

        snprintf(reply, 1024, "550 directory \"%s\" can't open.\r\n", session->currentdir);
        send(session->fd, reply, strlen(reply), 0);
        rt_free(reply);
        return RT_EOK;
    }

    closedir(dir);

    reply = rt_malloc(1024);
    if(reply == RT_NULL)
        return -RT_ERROR;

    snprintf(reply, 1024, "250 Changed to directory \"%s\"\r\n", session->currentdir);
    send(session->fd, reply, strlen(reply), 0);
    rt_free(reply);
    return RT_EOK;
}

static int cdup_cmd_fn(struct ftp_session *session, char *cmd, char *cmd_param)
{
    if(build_full_path(session->currentdir, sizeof(session->currentdir), "..") != RT_EOK)
        return -RT_ERROR;

    char *reply = RT_NULL;
    DIR *dir = opendir(session->currentdir);
    if (dir == RT_NULL)
    {
        reply = rt_malloc(1024);
        if(reply == RT_NULL)
            return -RT_ERROR;

        snprintf(reply, 1024, "550 directory \"%s\" can't open.\r\n", session->currentdir);
        send(session->fd, reply, strlen(reply), 0);
        rt_free(reply);
        return RT_EOK;
    }

    closedir(dir);

    reply = rt_malloc(1024);
    if(reply == RT_NULL)
        return -RT_ERROR;

    snprintf(reply, 1024, "250 Changed to directory \"%s\"\r\n", session->currentdir);
    send(session->fd, reply, strlen(reply), 0);
    rt_free(reply);
    return RT_EOK;
}

static int mkd_cmd_fn(struct ftp_session *session, char *cmd, char *cmd_param)
{
    char *reply = RT_NULL;
    if(session->is_anonymous)
    {
        reply = "550 Permission denied.\r\n";
        send(session->fd, reply, strlen(reply), 0);
        return RT_EOK;
    }

    char path[256];
    snprintf(path, sizeof(path), "%s", session->currentdir);
    if(build_full_path(path, sizeof(path), cmd_param) != RT_EOK)
        return -RT_ERROR;

    reply = rt_malloc(1024);
    if(reply == RT_NULL)
        return -RT_ERROR;

    if(ftp_create_dir(path) != RT_EOK)
        snprintf(reply, 1024, "550 directory \"%s\" create error.\r\n", path);
    else
        snprintf(reply, 1024, "257 directory \"%s\" successfully created.\r\n", path);

    send(session->fd, reply, strlen(reply), 0);
    rt_free(reply);
    return RT_EOK;
}

static int rmd_cmd_fn(struct ftp_session *session, char *cmd, char *cmd_param)
{
    char *reply = RT_NULL;
    if(session->is_anonymous)
    {
        reply = "550 Permission denied.\r\n";
        send(session->fd, reply, strlen(reply), 0);
        return RT_EOK;
    }

    char path[256];
    snprintf(path, sizeof(path), "%s", session->currentdir);
    if(build_full_path(path, sizeof(path), cmd_param) != RT_EOK)
        return -RT_ERROR;

    reply = rt_malloc(1024);
    if(reply == RT_NULL)
        return -RT_ERROR;

    if(unlink(path) != 0)
        snprintf(reply, 1024, "550 directory \"%s\" delete error.\r\n", path);
    else
        snprintf(reply, 1024, "257 directory \"%s\" successfully deleted.\r\n", path);

    send(session->fd, reply, strlen(reply), 0);
    rt_free(reply);
    return RT_EOK;
}

static int dele_cmd_fn(struct ftp_session *session, char *cmd, char *cmd_param)
{
    char *reply = RT_NULL;
    if(session->is_anonymous)
    {
        reply = "550 Permission denied.\r\n";
        send(session->fd, reply, strlen(reply), 0);
        return RT_EOK;
    }

    char path[256];
    snprintf(path, sizeof(path), "%s", session->currentdir);
    if(build_full_path(path, sizeof(path), cmd_param) != RT_EOK)
        return -RT_ERROR;

    reply = rt_malloc(1024);
    if(reply == RT_NULL)
        return -RT_ERROR;

    if(unlink(path) != 0)
        snprintf(reply, 1024, "550 file \"%s\" delete error.\r\n", path);
    else
        snprintf(reply, 1024, "250 file \"%s\" successfully deleted.\r\n", path);

    send(session->fd, reply, strlen(reply), 0);
    rt_free(reply);
    return RT_EOK;
}

static int size_cmd_fn(struct ftp_session *session, char *cmd, char *cmd_param)
{
    char *reply = RT_NULL;
    char path[256];
    snprintf(path, sizeof(path), "%s", session->currentdir);
    if(build_full_path(path, sizeof(path), cmd_param) != RT_EOK)
        return -RT_ERROR;

    struct stat s;
    rt_memset(&s, 0, sizeof(struct stat));
    if(stat(path, &s) != 0)
    {
        reply = rt_malloc(1024);
        if(reply == RT_NULL)
            return -RT_ERROR;

        snprintf(reply, 1024, "550 \"%s\" : not a regular file\r\n", path);
        send(session->fd, reply, strlen(reply), 0);
        rt_free(reply);
        return RT_EOK;
    }

    if(!S_ISREG(s.st_mode))
    {
        reply = rt_malloc(1024);
        if(reply == RT_NULL)
            return -RT_ERROR;

        snprintf(reply, 1024, "550 \"%s\" : not a regular file\r\n", path);
        send(session->fd, reply, strlen(reply), 0);
        rt_free(reply);
        return RT_EOK;
    }

    reply = rt_malloc(1024);
    if(reply == RT_NULL)
        return -RT_ERROR;

    snprintf(reply, 1024, "213 %d\r\n", s.st_size);
    send(session->fd, reply, strlen(reply), 0);
    rt_free(reply);
    return RT_EOK;
}

static int rest_cmd_fn(struct ftp_session *session, char *cmd, char *cmd_param)
{
    char *reply = RT_NULL;

    int offset = atoi(cmd_param);
    if(offset < 0)
    {
        reply = "504 invalid parameter.\r\n";
        send(session->fd, reply, strlen(reply), 0);
        session->offset = 0;
        return RT_EOK;
    }

    reply = "350 Send RETR or STOR to start transfert.\r\n";
    send(session->fd, reply, strlen(reply), 0);
    session->offset = offset;
    return RT_EOK;
}

static int retr_cmd_fn(struct ftp_session *session, char *cmd, char *cmd_param)
{
    char *reply = RT_NULL;
    if (session->port_pasv_fd < 0)
    {
        reply = "502 Not Implemented.\r\n";
        send(session->fd, reply, strlen(reply), 0);
        session->offset = 0;
        return RT_EOK;
    }

    char path[256];
    snprintf(path, sizeof(path), "%s", session->currentdir);
    if(build_full_path(path, sizeof(path), cmd_param) != RT_EOK)
        return -RT_ERROR;

    FILE *fp = fopen(path, "rb");
    if(fp == RT_NULL)
    {
        reply = rt_malloc(1024);
        if(reply == RT_NULL)
            return -RT_ERROR;

        snprintf(reply, 1024, "550 \"%s\" : not a regular file\r\n", path);
        send(session->fd, reply, strlen(reply), 0);
        rt_free(reply);
        session->offset = 0;
        return RT_EOK;
    }

    int rc = -RT_ERROR;
    int file_size = 0;
    do
    {
        fseek(fp, 0, SEEK_END);
        file_size = ftell(fp);
        rewind(fp);
        if(file_size <= 0)
            break;

        rc = RT_EOK;
    }while(0);

    if(rc != RT_EOK)
    {
        fclose(fp);

        reply = rt_malloc(1024);
        if(reply == RT_NULL)
            return -RT_ERROR;

        snprintf(reply, 1024, "550 \"%s\" : not a regular file\r\n", path);
        send(session->fd, reply, strlen(reply), 0);
        rt_free(reply);
        session->offset = 0;
        return RT_EOK;
    }

    reply = rt_malloc(4096);
    if(reply == RT_NULL)
    {
        fclose(fp);
        return -RT_ERROR;
    }

    if((session->offset > 0) && (session->offset < file_size))
    {
        fseek(fp, session->offset, SEEK_SET);
        snprintf(reply, 4096, "150 Opening binary mode data connection for \"%s\" (%d/%d bytes).\r\n",
                 path, file_size - session->offset, file_size);
    }
    else
    {
        snprintf(reply, 4096, "150 Opening binary mode data connection for \"%s\" (%d bytes).\r\n",
                 path, file_size);
    }
    send(session->fd, reply, strlen(reply), 0);

    int recv_bytes = 0;
    int result = RT_EOK;
    while((recv_bytes = fread(reply, 1, 4096, fp)) > 0)
    {
        if(send(session->port_pasv_fd, reply, recv_bytes, 0) != recv_bytes)
        {
            result = -RT_ERROR;
            break;
        }
    }

    rt_free(reply);
    fclose(fp);
    close(session->port_pasv_fd);
    session->port_pasv_fd = -1;

    if(result != RT_EOK)
        return -RT_ERROR;

    reply = "226 Finished.\r\n";
    send(session->fd, reply, strlen(reply), 0);
    session->offset = 0;
    return RT_EOK;
}

static int stor_cmd_receive(int socket, uint8_t *buf, int bufsz, int timeout)
{
    if((socket < 0) || (buf == RT_NULL) || (bufsz <= 0) || (timeout <= 0))
        return -RT_ERROR;

    int len = 0;
    int rc = 0;
    fd_set rset;
    struct timeval tv;

    FD_ZERO(&rset);
    FD_SET(socket, &rset);
    tv.tv_sec = timeout / 1000;
    tv.tv_usec = (timeout % 1000) * 1000;

    while(bufsz > 0)
    {
        rc = select(socket + 1, &rset, RT_NULL, RT_NULL, &tv);
        if(rc <= 0)
            break;

        rc = recv(socket, buf + len, bufsz, MSG_DONTWAIT);
        if(rc <= 0)
            break;

        len += rc;
        bufsz -= rc;

        tv.tv_sec = 3;
        tv.tv_usec = 0;
        FD_ZERO(&rset);
        FD_SET(socket, &rset);
    }

    if(rc >= 0)
        rc = len;

    return rc;
}

static int stor_cmd_fn(struct ftp_session *session, char *cmd, char *cmd_param)
{
    session->offset = 0;

    char *reply = RT_NULL;
    if(session->is_anonymous)
    {
        reply = "550 Permission denied.\r\n";
        send(session->fd, reply, strlen(reply), 0);
        return RT_EOK;
    }

    if (session->port_pasv_fd < 0)
    {
        reply = "502 Not Implemented.\r\n";
        send(session->fd, reply, strlen(reply), 0);
        return RT_EOK;
    }

    char path[256];
    snprintf(path, sizeof(path), "%s", session->currentdir);
    if(build_full_path(path, sizeof(path), cmd_param) != RT_EOK)
        return -RT_ERROR;

    FILE *fp = fopen(path, "wb");
    if(fp == RT_NULL)
    {
        reply = rt_malloc(1024);
        if(reply == RT_NULL)
            return -RT_ERROR;

        snprintf(reply, 1024, "550 Cannot open \"%s\" for writing.\r\n", path);
        send(session->fd, reply, strlen(reply), 0);
        rt_free(reply);
        return RT_EOK;
    }

    reply = rt_malloc(4096);
    if(reply == RT_NULL)
    {
        fclose(fp);
        return -RT_ERROR;
    }

    snprintf(reply, 4096, "150 Opening binary mode data connection for \"%s\".\r\n", path);
    send(session->fd, reply, strlen(reply), 0);

    int result = RT_EOK;
    int timeout = 3000;
    while(1)
    {
        int recv_bytes = stor_cmd_receive(session->port_pasv_fd, (uint8_t *)reply, 4096, timeout);
        if(recv_bytes < 0)
        {
            result = -RT_ERROR;
            break;
        }
        if(recv_bytes == 0)
            break;
        if(fwrite(reply, recv_bytes, 1, fp) != 1)
        {
            result = -RT_ERROR;
            break;
        }

        timeout = 3000;
    }

    rt_free(reply);
    fclose(fp);
    close(session->port_pasv_fd);
    session->port_pasv_fd = -1;

    if(result != RT_EOK)
        return -RT_ERROR;

    reply = "226 Finished.\r\n";
    send(session->fd, reply, strlen(reply), 0);
    return RT_EOK;
}

static struct ftp_session_cmd session_cmds[] =
{
    {"PORT", port_cmd_fn},
    {"PWD", pwd_cmd_fn},
    {"XPWD", pwd_cmd_fn},
    {"TYPE", type_cmd_fn},
    {"SYST", syst_cmd_fn},
    {"QUIT", quit_cmd_fn},
    {"LIST", list_cmd_fn},
    {"NLST", nlist_cmd_fn},
    {"CWD", cwd_cmd_fn},
    {"CDUP", cdup_cmd_fn},
    {"MKD", mkd_cmd_fn},
    {"RMD", rmd_cmd_fn},
    {"DELE", dele_cmd_fn},
    {"SIZE", size_cmd_fn},
    {"REST", rest_cmd_fn},
    {"RETR", retr_cmd_fn},
    {"STOR", stor_cmd_fn}
};

int ftp_session_cmd_process(struct ftp_session *session, char *cmd, char *cmd_param)
{
    int array_cnt = sizeof(session_cmds) / sizeof(session_cmds[0]);
    struct ftp_session_cmd *session_cmd = RT_NULL;

    for (int i = 0; i < array_cnt; i++)
    {
        if(strstr(cmd, session_cmds[i].cmd) == cmd)
        {
            session_cmd = &session_cmds[i];
            break;
        }
    }

    if(session_cmd == RT_NULL)
    {
        char *reply = "502 Not Implemented.\r\n";
        send(session->fd, reply, strlen(reply), 0);
        return RT_EOK;
    }

    int result = session_cmd->cmd_fn(session, cmd, cmd_param);

    return result;
}
