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
parse_options(int argc,
              const char **argv,
              const char **_principal,
              const char **_socket_path,
              const char **_keytab_path)
{
    poptContext pc;
    char opt;
    int ret;
    int i;

    struct poptOption options[] = {
        POPT_AUTOHELP
        { "socket-path", 's', POPT_ARG_STRING, _socket_path, 0, "Path to the server socket", NULL },
        { "principal", 'p', POPT_ARG_STRING, _principal, 0, "Kerberos service principal to acquire", NULL },
        { "keytab", 'k', POPT_ARG_STRING, _keytab_path, 0, "Path to Kerberos keytab that contains credentials for the principal", NULL },
        POPT_TABLEEND
    };

    if (_keytab_path == NULL) {
        for (i = 0; options[i].longName != NULL; i++) {
            if (strcmp(options[i].longName, "keytab") == 0) {
                memset(&options[i], 0, sizeof(struct poptOption));
                break;
            }
        }
    }

    pc = poptGetContext(NULL, argc, argv, options, 0);
    while ((opt = poptGetNextOpt(pc)) > 0) {

    }

    if (opt != -1 || *_principal == NULL || *_socket_path == NULL) {
        poptPrintUsage(pc, stderr, 0);
        return EINVAL;
    }

    poptFreeContext(pc);
    return 0;
}

const char *server_socket_path = NULL;
int server_socket_fd = -1;

void signal_stop_server(int sig)
{
    puts("Terminating server.\n");
    if (server_socket_path != NULL) {
        unlink(server_socket_path);
    }

    if (server_socket_fd != -1) {
        close(server_socket_fd);
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
        fprintf(stderr, "Unable to bind to %s [%d]: %s\n", socket_path, ret, strerror(ret));
        return ret;
    }

    server_socket_path = socket_path;
    server_socket_fd = fd;

    ret = listen(fd, 1);
    if (ret != 0) {
        ret = errno;
        fprintf(stderr, "Unable to listen at %s [%d]: %s\n", socket_path, ret, strerror(ret));
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
        fprintf(stderr, "Unable to connect to %s [%d]: %s\n", socket_path, ret, strerror(ret));
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
    major = gss_import_name(&minor, &name_buf, 0, _name);
    if (GSS_ERROR(major)) {
        fprintf(stderr, "Could not import name\n");
        return EIO;
    }

    return 0;
}

static int
read_all(int fd, void *buf, size_t len) {
    size_t remaining = len;
    ssize_t num;

    while (remaining != 0) {
        num = read(fd, buf, remaining);
        if (num == -1) {
            return errno;
        }

        remaining -= num;
    }

    return 0;
}

static int
read_buf(int fd, uint8_t **_buf, size_t *_len)
{
    size_t len;
    uint8_t *buf;
    int ret;

    ret = read_all(fd, &len, sizeof(size_t));
    if (ret != 0) {
        return ret;
    }

    buf = malloc(len);
    if (buf == NULL) {
        return ENOMEM;
    }
    memset(buf, 0, len);

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
write_all(int fd, void *buf, size_t len) {
    size_t remaining = len;
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

static int
write_buf(int fd, uint8_t *buf, size_t len)
{
    int ret;

    ret = write_all(fd, &len, sizeof(size_t));
    if (ret != 0) {
        return ret;
    }

    ret = write_all(fd, buf, len);

    return ret;
}

int
establish_context(const char *principal,
                  gss_cred_id_t creds,
                  OM_uint32 flags,
                  int fd,
                  bool initiator)
{
    bool established;
    gss_ctx_id_t ctx = GSS_C_NO_CONTEXT;
    gss_buffer_desc input_token = GSS_C_EMPTY_BUFFER;
    gss_buffer_desc output_token = GSS_C_EMPTY_BUFFER;
    gss_name_t target_name = GSS_C_NO_NAME;
    gss_OID mech_type;
    OM_uint32 major = 0;
    OM_uint32 minor = 0;
    OM_uint32 ret_flags;
    int ret;

    if (initiator) {
        ret = set_name(principal, &target_name);
        if (ret != 0) {
            return ret;
        }
    } else {
        ret = read_buf(fd, (uint8_t **)&input_token.value, &input_token.length);
        if (ret != 0) {
            fprintf(stderr, "Unable to read data [%d]: %s\n", ret, strerror(ret));;
            goto done;
        }
    }

    /* Do the handshake. */
    established = false;
    while (!established) {
        if (initiator) {
            major = gss_init_sec_context(&minor, creds, &ctx,
                                        target_name, GSS_C_NO_OID, flags, 0,
                                        NULL, &input_token, NULL, &output_token,
                                        &ret_flags, NULL);
        } else {
            major = gss_accept_sec_context(&minor, &ctx, creds, &input_token,
                                        NULL, &target_name, &mech_type,
                                        &output_token, &ret_flags, NULL, NULL);
        }

        free(input_token.value);
        memset(&input_token, 0, sizeof(gss_buffer_desc));

        if (major & GSS_S_CONTINUE_NEEDED || output_token.length > 0) {
            ret = write_buf(fd, output_token.value, output_token.length);
            if (ret != 0) {
                fprintf(stderr, "Unable to write data [%d]: %s\n", ret, strerror(ret));;
                goto done;
            }
        }

        gss_release_buffer(&minor, &output_token);
        if (GSS_ERROR(major)) {
            fprintf(stderr, "gss_init_sec_context() error major 0x%x\n", major);
            ret = EIO;
            goto done;
        }

        if (major & GSS_S_CONTINUE_NEEDED) {
            ret = read_buf(fd, (uint8_t **)&input_token.value, &input_token.length);
            if (ret != 0) {
                fprintf(stderr, "Unable to read data [%d]: %s\n", ret, strerror(ret));;
                goto done;
            }
        } else if (major == GSS_S_COMPLETE) {
            established = true;
        } else {
            fprintf(stderr, "major not complete or continue but not error\n");
            ret = EIO;
            goto done;
        }
    }

    if (ret_flags & flags != flags) {
        fprintf(stderr, "Negotiated context does not support requested flags\n");
        ret = EIO;
        goto done;
    }

    ret = 0;

done:
    /* Do not request a context deletion token; pass NULL. */
    gss_delete_sec_context(&minor, &ctx, NULL);
    gss_release_name(&minor, &target_name);

    return ret;
}