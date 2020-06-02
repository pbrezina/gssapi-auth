/*
    Authors:
        Pavel Březina <pbrezina@redhat.com>

    Copyright (C) 2020 Red Hat

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <errno.h>
#include <gssapi.h>
#include <popt.h>
#include <signal.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

int
parse_client_options(int argc,
                     const char **argv,
                     const char **_name,
                     const char **_socket_path)
{
    poptContext pc;
    char opt;
    int ret;
    int i;

    struct poptOption options[] = {
        POPT_AUTOHELP
        { "socket-path", 's', POPT_ARG_STRING, _socket_path, 0,
          "Path to the server socket", NULL },
        { "name", 'n', POPT_ARG_STRING, _name, 0,
          "Hostbased service name", NULL },
        POPT_TABLEEND
    };

    pc = poptGetContext(NULL, argc, argv, options, 0);
    while ((opt = poptGetNextOpt(pc)) > 0) {

    }

    if (opt != -1 || *_name == NULL || *_socket_path == NULL) {
        poptPrintUsage(pc, stderr, 0);
        return EINVAL;
    }

    poptFreeContext(pc);
    return 0;
}

int
parse_server_options(int argc,
                     const char **argv,
                     const char **_socket_path,
                     const char **_keytab_path)
{
    poptContext pc;
    char opt;
    int ret;
    int i;

    struct poptOption options[] = {
        POPT_AUTOHELP
        { "socket-path", 's', POPT_ARG_STRING, _socket_path, 0,
          "Path to the server socket", NULL },
        { "keytab", 'k', POPT_ARG_STRING, _keytab_path, 0,
          "Path to Kerberos keytab that contains credentials", NULL },
        POPT_TABLEEND
    };

    pc = poptGetContext(NULL, argc, argv, options, 0);
    while ((opt = poptGetNextOpt(pc)) > 0) {

    }

    if (opt != -1 || *_socket_path == NULL) {
        poptPrintUsage(pc, stderr, 0);
        return EINVAL;
    }

    poptFreeContext(pc);
    return 0;
}

const char *server_socket_path = NULL;

void signal_stop_server(int sig)
{
    puts("Terminating server.\n");
    if (server_socket_path != NULL) {
        unlink(server_socket_path);
    }

    exit(0);
}

int
init_server(const char *socket_path,
            int *_fd)
{
    struct sockaddr_un addr;
    int len;
    int ret;
    int fd;

    if (strlen(socket_path) > 107) {
        fprintf(stderr, "Socket path is too long\n");
        return EINVAL;
    }

    signal(SIGINT, signal_stop_server);
    signal(SIGTERM, signal_stop_server);

    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd == -1) {
        fprintf(stderr, "Unable to create socket\n");
        return EIO;
    }

    addr.sun_family = AF_UNIX;
    strcpy(addr.sun_path, socket_path);
    unlink(addr.sun_path);

    len = strlen(addr.sun_path) + sizeof(addr.sun_family);
    ret = bind(fd, (struct sockaddr *)&addr, len);
    if (ret != 0) {
        ret = errno;
        fprintf(stderr, "Unable to bind to %s [%d]: %s\n", socket_path,
                ret, strerror(ret));
        return ret;
    }

    server_socket_path = socket_path;

    ret = listen(fd, 1);
    if (ret != 0) {
        ret = errno;
        fprintf(stderr, "Unable to listen at %s [%d]: %s\n", socket_path,
                ret, strerror(ret));
        return ret;
    }

    *_fd = fd;

    return 0;
}

int
init_client(const char *socket_path,
            int *_fd)
{
    struct sockaddr_un addr;
    int len;
    int ret;
    int fd;

    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd == -1) {
        fprintf(stderr, "Unable to create socket\n");
        return EIO;
    }

    addr.sun_family = AF_UNIX;
    strcpy(addr.sun_path, socket_path);

    len = strlen(addr.sun_path) + sizeof(addr.sun_family);
    ret = connect(fd, (struct sockaddr *)&addr, len);
    if (ret != 0) {
        ret = errno;
        fprintf(stderr, "Unable to connect to %s [%d]: %s\n", socket_path,
                ret, strerror(ret));
        return ret;
    }

    *_fd = fd;

    return 0;
}

int
set_name(const char *principal,
         gss_name_t *_name)
{
    gss_buffer_desc name_buf = GSS_C_EMPTY_BUFFER;
    OM_uint32 major = 0;
    OM_uint32 minor = 0;

    name_buf.value = (void*)principal;
    name_buf.length = strlen(name_buf.value);
    major = gss_import_name(&minor, &name_buf, GSS_C_NT_HOSTBASED_SERVICE,
                            _name);
    if (GSS_ERROR(major)) {
        fprintf(stderr, "Could not import name\n");
        return EIO;
    }

    return 0;
}

int
get_name(gss_name_t name,
         char **_name)
{
    OM_uint32 major = 0;
    OM_uint32 minor = 0;
    gss_buffer_desc buf = GSS_C_EMPTY_BUFFER;
    char *exported;

    major = gss_display_name(&minor, name, &buf, NULL);
    if (major != GSS_S_COMPLETE) {
        fprintf(stderr, "Unable to export name\n");
        return EIO;
    }

    exported = malloc(buf.length);
    if (exported == NULL) {
        gss_release_buffer(&minor, &buf);
        fprintf(stderr, "Out of memory\n");
        return ENOMEM;
    }

    strncpy(exported, buf.value, buf.length);
    gss_release_buffer(&minor, &buf);

    *_name = exported;

    return 0;
}

static int
read_all(int fd, void *buf, uint32_t len) {
    uint32_t remaining = len;
    ssize_t num;

    while (remaining != 0) {
        num = read(fd, buf, remaining);
        if (num == 0) {
            return ENOLINK;
        } else if (num == -1) {
            return errno;
        }

        remaining -= num;
    }

    return 0;
}

int
read_buf(int fd, uint8_t **_buf, size_t *_len)
{
    uint32_t len;
    uint8_t *buf;
    int ret;

    ret = read_all(fd, &len, sizeof(uint32_t));
    if (ret != 0) {
        return ret;
    }

    buf = malloc(len);
    if (buf == NULL) {
        return ENOMEM;
    }

    ret = read_all(fd, buf, len);
    if (ret != 0) {
        free(buf);
        return ret;
    }

    *_len = len;
    *_buf = buf;

    return 0;
}

static int
write_all(int fd, void *buf, uint32_t len) {
    uint32_t remaining = len;
    ssize_t num;

    while (remaining != 0) {
        num = write(fd, buf, remaining);
        if (num == -1) {
            return errno;
        }

        remaining -= num;
    }

    return 0;
}

int
write_buf(int fd, uint8_t *buf, size_t len)
{
    int ret;

    ret = write_all(fd, &len, sizeof(uint32_t));
    if (ret != 0) {
        return ret;
    }

    ret = write_all(fd, buf, len);

    return ret;
}
