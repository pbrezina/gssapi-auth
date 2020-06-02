# Example of authentication using GSSAPI

## How to test

1. Build: `make all`
2. Run server: `./gssapi-auth-server -s ./socket -k /path/to/keytab`
3. Run client: `./gssapi-auth-client -n service_name -s ./socket`

Where:
* `service_name` is the host based service name to authenticate with
* `./socket` is path where the UNIX socket will be created
* `/path/to/keytab` is path to the Kerberos keytab that contains `service_name` credentials

## Example

### Server:

```
$ ./gssapi-auth-server -s ./socket -k /path/to/keytab
Trying to establish security context:
  Socket: ./socket
  Keytab: /path/to/keytab
Listening for connections...
Accepted connection: 4
Security context with admin@IPA.VM successfully established.
```

### Client:

```
$ ./gssapi-auth-client -n host@master.client.vm -s ./socket
Trying to establish security context:
  Service Name: host@master.client.vm
  Socket: ./socket
Security context with host@master.client.vm successfully established.
```

## Notes

As an example, you can find the code that establish security content between
client and the server in [`initiator_establish_context()`] and
[`acceptor_establish_context()`].

[`initiator_establish_context()`]: ./src/client.c#L32
[`acceptor_establish_context()`]: ./src/server.c#L35
