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
parse_options(int argc,
              const char **argv,
              const char **_principal,
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
establish_context(const char *principal,
                  gss_cred_id_t creds,
                  OM_uint32 flags,
                  int fd,
                  bool initiator);

#endif /* _UTILS_H_ */
