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
#include <gssapi/gssapi_krb5.h>

#include "utils.h"

static int
acquire_creds(const char *principal,
              const char *keytab,
              gss_cred_id_t *_creds)
{
    gss_name_t name = GSS_C_NO_NAME;
    OM_uint32 major = 0;
    OM_uint32 minor = 0;
    int ret;

    if (keytab != NULL) {
        major = krb5_gss_register_acceptor_identity(keytab);
        if (GSS_ERROR(major)) {
            fprintf(stderr, "Unable to set keytab location\n");
            return EIO;
        }
    }

    ret = set_name(principal, &name);
    if (ret != 0) {
        return ret;
    }

    major = gss_acquire_cred(&minor, name, 0, GSS_C_NULL_OID_SET, GSS_C_ACCEPT,
                             _creds, NULL, NULL);
    gss_release_name(&minor, &name);
    if (GSS_ERROR(major)) {
        fprintf(stderr, "Unable to acquire credentials\n");
        return EIO;
    }

    return 0;
}

int
server_loop(int socket_fd, const char *principal, gss_cred_id_t creds)
{
    struct sockaddr_un client;
    socklen_t client_len = sizeof(client);
    char buf[100] = {'\0'};
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

        ret = establish_context(principal, creds, GSS_C_MUTUAL_FLAG,
                                client_fd, false);
        if (ret != 0) {
            fprintf(stderr, "Unable to establish context with client %d\n",
                    client_fd);
        }

        printf("Security context with %s successfully established.\n", principal);
        close(client_fd);
    }

    return 0;
}

int main(int argc, const char **argv)
{
    const char *principal;
    const char *socket_path;
    const char *keytab_path = NULL;
    gss_cred_id_t creds = GSS_C_NO_CREDENTIAL;
    OM_uint32 minor = 0;
    int socket_fd;
    int ret;

    ret = parse_options(argc, argv, &principal, &socket_path, &keytab_path);
    if (ret != 0) {
        goto done;
    }

    printf("Trying to establish security context:\n");
    printf("  Service Principal: %s\n",  principal);
    printf("  Socket: %s\n", socket_path);
    printf("  Keytab: %s\n", keytab_path != NULL ? keytab_path : "default");

    ret = init_server(socket_path, &socket_fd);
    if (ret != 0) {
        fprintf(stderr, "Unable to create server!\n");
        goto done;
    }

    ret = acquire_creds(principal, keytab_path, &creds);
    if (ret != 0) {
        goto done;
    }

    ret = server_loop(socket_fd, principal, creds);

    ret = 0;

done:
    if (creds != GSS_C_NO_CREDENTIAL) {
        gss_release_cred(&minor, &creds);
    }

    if (ret != 0) {
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}