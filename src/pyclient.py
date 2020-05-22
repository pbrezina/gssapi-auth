import gssapi

secctx = gssapi.SecurityContext(
    name=gssapi.Name('host/master.client.vm@IPA.vm'),
    usage='initiate'
)

input_token = None
try:
    while not secctx.complete:
        output_token = secctx.step(input_token)
        if output_token is not None and len(output_token) > 0:
            # sock.sendall(output_token)
            pass

        if not secctx.complete:
            # input_token = recvall(sock)
            pass
except gssapi.exceptions.GSSError as e:
     print('Error: {}'.format(str(e)))
