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
#include <string.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#include "utils.h"

static int
initiator_establish_context(const char *service,
                            OM_uint32 flags,
                            int fd)
{
    bool established;
    gss_ctx_id_t ctx = GSS_C_NO_CONTEXT;
    gss_buffer_desc input_token = GSS_C_EMPTY_BUFFER;
    gss_buffer_desc output_token = GSS_C_EMPTY_BUFFER;
    gss_buffer_t buffer;
    gss_name_t target_name = GSS_C_NO_NAME;
    gss_OID mech_type;
    OM_uint32 major = 0;
    OM_uint32 minor = 0;
    OM_uint32 ctx_minor = 0;
    OM_uint32 ret_flags;
    int ret;

    ret = set_name(service, &target_name);
    if (ret != 0) {
        return ret;
    }

    /* Do the handshake. */
    established = false;
    while (!established) {
        major = gss_init_sec_context(&ctx_minor, GSS_C_NO_CREDENTIAL, &ctx,
                                     target_name, GSS_C_NO_OID, flags, 0,
                                     NULL, &input_token, NULL, &output_token,
                                     &ret_flags, NULL);

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
            fprintf(stderr, "gss_init_sec_context() [maj:0x%x, min:0x%x]\n",
                    major, ctx_minor);
            print_gss_status("GSS Major", major, GSS_C_GSS_CODE);
            print_gss_status("GSS Minor", ctx_minor, GSS_C_MECH_CODE);
            ret = EIO;
            goto done;
        }

        if (major == GSS_S_CONTINUE_NEEDED) {
            ret = read_buf(fd, (uint8_t **)&input_token.value,
                           &input_token.length);
            if (ret != 0) {
                fprintf(stderr, "Unable to read data [%d]: %s\n",
                        ret, strerror(ret));;
                goto done;
            }
        } else if (major == GSS_S_COMPLETE) {
            established = true;
        } else {
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

    ret = 0;

done:
    /* Do not request a context deletion token; pass NULL. */
    gss_delete_sec_context(&minor, &ctx, NULL);
    gss_release_name(&minor, &target_name);

    return ret;
}

int main(int argc, const char **argv)
{
    const char *service;
    const char *socket_path;
    int fd = -1;
    int ret;

    ret = parse_client_options(argc, argv, &service, &socket_path);
    if (ret != 0) {
        goto done;
    }

    printf("Trying to establish security context:\n");
    printf("  Service Name: %s\n", service);
    printf("  Socket: %s\n", socket_path);

    ret = init_client(socket_path, &fd);
    if (ret != 0) {
        fprintf(stderr, "Unable to connect to the server!\n");
        goto done;
    }

    ret = initiator_establish_context(service, GSS_C_MUTUAL_FLAG, fd);
    if (ret != 0) {
        fprintf(stderr, "Unable to establish security context!\n");
        goto done;
    }

    printf("Security context with %s successfully established.\n", service);

    ret = 0;

done:
    if (fd != -1) {
        close(fd);
    }

    if (ret != 0) {
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
