all: posttest.cgi
INCD = -I/home/hello/src/mariadb/include/mariadb -I/home/hello/src/openssl-1.1.1w/include
DB_LIB = /home/hello/src/mariadb/lib/mariadb/libmysqlclient.a -ldl -lrt -lpthread -lm /home/hello/src/openssl-1.1.1w/libssl.a /home/hello/src/openssl-1.1.1w/libcrypto.a
posttest.cgi: post.c
	gcc -w -o posttest.cgi post.c ${INCD} ${DB_LIB}

clean:
	rm -f posttest.cgi
