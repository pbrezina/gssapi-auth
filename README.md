# Example of authentication using GSSAPI

## How to test

1. Build: `make all`
2. Run server: `./gssapi-auth-server -p principal -s ./socket -k /path/to/keytab`
3. Run client: `./gssapi-auth-client -p principal -s ./socket`

Where:
* `principal` is the principal to authenticate with
* `./socket` is path where the UNIX socket will be created
* `/path/to/keytab` is path to the keytab that contains `principal` credentials

## Example

### Server:

```
$ ./gssapi-auth-server -p host/master.client.vm@IPA.VM -s ./socket -k /home/pbrezina/workspace/sssd-test-suite/shared-enrollment/client/ipa.keytab
Trying to establish security context:
  Service Principal: host/master.client.vm@IPA.VM
  Socket: ./socket
  Keytab: /home/pbrezina/workspace/sssd-test-suite/shared-enrollment/client/ipa.keytab
Listening for connections...
Accepted connection: 6
Security context with host/master.client.vm@IPA.VM successfully established.
```

### Client:

```
$ ./gssapi-auth-client -p host/master.client.vm@IPA.VM -s ./socket
Trying to establish security context:
  Service Principal: host/master.client.vm@IPA.VM
  Socket: ./socket
Security context with host/master.client.vm@IPA.VM successfully established.
```

## Notes

As an example, you can find the code that establish security content between
client and the server in `src/utils.c:establish_context()` and the code that
load in server credentials at `src/server.c:acquire_creds()`.
