all: gssapi-auth-client gssapi-auth-server

gssapi-auth-client: src/client.c src/utils.c
	gcc -ggdb3 -o gssapi-auth-client src/client.c src/utils.c -lgssapi_krb5 -ltalloc -ltevent -lpopt

gssapi-auth-server: src/server.c src/utils.c
	gcc -ggdb3 -o gssapi-auth-server src/server.c src/utils.c -lgssapi_krb5 -ltalloc -ltevent -lpopt

clean:
	rm -f gssapi-auth-client gssapi-auth-server
