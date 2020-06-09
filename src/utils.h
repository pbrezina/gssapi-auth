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

#ifndef _UTILS_H_
#define _UTILS_H_

int
parse_client_options(int argc,
                     const char **argv,
                     const char **_name,
                     const char **_socket_path);

int
parse_server_options(int argc,
                     const char **argv,
                     const char **_socket_path,
                     const char **_keytab_path);

int
init_server(const char *socket_path,
            int *_fd);

int
init_client(const char *socket_path,
            int *_fd);

int
set_name(const char *principal,
         gss_name_t *_name);

int
get_name(gss_name_t name,
         char **_name);

void
print_gss_status(const char *message, OM_uint32 status_code, int type);

int
read_buf(int fd, uint8_t **_buf, size_t *_len);

int
write_buf(int fd, uint8_t *buf, size_t len);

#endif /* _UTILS_H_ */
