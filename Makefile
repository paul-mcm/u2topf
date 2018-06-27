CC = gcc
EXEC = u2topfd
INSTALL_DIR = /usr/local/sbin

objects = errorlog.o

errorlog.o: errorlog.h
	$(CC) -c errorlog.c -o errorlog.o
        
all: $(objects)
	$(CC) -o $(EXEC) $(objects) u2topfd.c
	@rm -f $(objects)

install:
	@cp $(EXEC) $(INSTALL_DIR)/$(EXEC)
	@cp ./rc.d/$(EXEC) /etc/rc.d/$(EXEC)
	@chmod 550 $(INSTALL_DIR)/$(EXEC)
	@chmod 550 /etc/rc.d/$(EXEC)
	@chown root:wheel $(INSTALL_DIR)/$(EXEC)
	@chown root:wheel /etc/rc.d/$(EXEC)

clean:
	@rm -f $(EXEC)
	@rm -f $(objecst)
