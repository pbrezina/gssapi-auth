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

#include <unistd.h>
#include <gssapi.h>
#include <talloc.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <stdbool.h>
#include <signal.h>
#include <stdlib.h>

#include "utils.h"

static int
acceptor_establish_context(OM_uint32 flags,
                           int fd,
                           char **_client)
{
    bool established;
    gss_ctx_id_t ctx = GSS_C_NO_CONTEXT;
    gss_buffer_desc input_token = GSS_C_EMPTY_BUFFER;
    gss_buffer_desc output_token = GSS_C_EMPTY_BUFFER;
    gss_name_t client_name = GSS_C_NO_NAME;
    gss_buffer_t exported_name = NULL;
    gss_OID mech_type;
    OM_uint32 major = 0;
    OM_uint32 minor = 0;
    OM_uint32 ctx_minor = 0;
    OM_uint32 ret_flags;
    char *str_name;
    int ret;

    /* Do the handshake. */
    established = false;
    while (!established) {
        ret = read_buf(fd, (uint8_t **)&input_token.value, &input_token.length);
        if (ret == ENOLINK) {
            fprintf(stderr,
                    "Client closed the connection before sending input data\n");
            goto done;
        } else if (ret != 0) {
            fprintf(stderr, "Unable to read data [%d]: %s\n",
                    ret, strerror(ret));;
            goto done;
        }

        major = gss_accept_sec_context(&ctx_minor, &ctx, GSS_C_NO_CREDENTIAL,
                                       &input_token, NULL, &client_name,
                                       &mech_type, &output_token, &ret_flags,
                                       NULL, NULL);

        free(input_token.value);
        memset(&input_token, 0, sizeof(gss_buffer_desc));

        if (major == GSS_S_CONTINUE_NEEDED || output_token.length > 0) {
            ret = write_buf(fd, output_token.value, output_token.length);
            if (ret != 0) {
                fprintf(stderr, "Unable to write data [%d]: %s\n",
                        ret, strerror(ret));;
                goto done;
            }
        }

        gss_release_buffer(&minor, &output_token);
        if (GSS_ERROR(major)) {
            fprintf(stderr, "gss_accept_sec_context() [maj:0x%x, min:0x%x]\n",
                    major, ctx_minor);
            print_gss_status("GSS Major", major, GSS_C_GSS_CODE);
            print_gss_status("GSS Minor", ctx_minor, GSS_C_MECH_CODE);
            ret = EIO;
            goto done;
        }

        if (major == GSS_S_COMPLETE) {
            established = true;
        } else if (major != GSS_S_CONTINUE_NEEDED) {
            fprintf(stderr, "Context is not established but major has "
                    "unexpected value: %x\n", major);
            ret = EIO;
            goto done;
        }
    }

    if (ret_flags & flags != flags) {
        fprintf(stderr, "Negotiated context does not support requested flags\n");
        ret = EIO;
        goto done;
    }

    ret = get_name(client_name, _client);

done:
    /* Do not request a context deletion token; pass NULL. */
    gss_delete_sec_context(&minor, &ctx, NULL);
    gss_release_name(&minor, &client_name);

    return ret;
}

int
server_loop(int socket_fd)
{
    struct sockaddr_un client;
    socklen_t client_len = sizeof(client);
    char buf[100] = {'\0'};
    char *client_name;
    int client_fd;
    int ret;

    puts("Listening for connections...");

    while (true) {
        client_fd = accept(socket_fd, (struct sockaddr *)&client, &client_len);
        if (client_fd == -1) {
            fprintf(stderr, "Unable to accept connection!\n");
            return EIO;
        }

        printf("Accepted connection: %d\n", client_fd);

        ret = acceptor_establish_context(GSS_C_MUTUAL_FLAG, client_fd,
                                         &client_name);
        if (ret != 0) {
            fprintf(stderr, "Unable to establish context with client %d\n",
                    client_fd);
            close(client_fd);
            continue;
        }

        printf("Security context with %s successfully established.\n",
               client_name);
        free(client_name);
        close(client_fd);
    }

    return 0;
}

int main(int argc, const char **argv)
{
    const char *principal;
    const char *socket_path;
    const char *keytab_path = NULL;
    int ret;
    int fd;

    ret = parse_server_options(argc, argv, &socket_path, &keytab_path);
    if (ret != 0) {
        goto done;
    }

    printf("Trying to establish security context:\n");
    printf("  Socket: %s\n", socket_path);
    printf("  Keytab: %s\n", keytab_path != NULL ? keytab_path : "default");

    if (keytab_path != NULL) {
        setenv("KRB5_KTNAME", keytab_path, 1);
    }

    ret = init_server(socket_path, &fd);
    if (ret != 0) {
        fprintf(stderr, "Unable to create server!\n");
        goto done;
    }

    ret = server_loop(fd);

done:
    if (ret != 0) {
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}