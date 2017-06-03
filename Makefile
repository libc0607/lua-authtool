
authtool.so:
	$(CC) -c auth_sock.c -fPIC -DDEBUG
	$(CC) auth_sock.o -fPIC -shared -o authtool.so

clean:
	rm -f *.so *.o

test:
	sudo lua test.lua
