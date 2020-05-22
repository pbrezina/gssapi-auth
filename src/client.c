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

int main(int argc, const char **argv)
{
    const char *principal;
    const char *socket_path;
    int socket_fd = -1;
    int ret;

    ret = parse_options(argc, argv, &principal, &socket_path, NULL);
    if (ret != 0) {
        goto done;
    }

    printf("Trying to establish security context:\n");
    printf("  Service Principal: %s\n",  principal);
    printf("  Socket: %s\n", socket_path);

    ret = init_client(socket_path, &socket_fd);
    if (ret != 0) {
        fprintf(stderr, "Unable to connect to the server!\n");
        goto done;
    }

    ret = establish_context(principal, GSS_C_NO_CREDENTIAL, GSS_C_MUTUAL_FLAG,
                            socket_fd, true);
    if (ret != 0) {
        fprintf(stderr, "Unable to establish security context!\n");
        goto done;
    }

    printf("Security context with %s successfully established.\n", principal);

    ret = 0;

done:
    if (socket_fd != -1) {
        close(socket_fd);
    }

    if (ret != 0) {
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}