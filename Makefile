CC = gcc
EXEC = u2topfd

objects = errorlog.o

errorlog.o: errorlog.h
	$(CC) -c errorlog.c -o errorlog.o
        
all: $(objects)
	$(CC) -o $(EXEC) $(objects) u2topfd.c
	@rm -f $(objects)

clean:
	@rm -f $(EXEC)
	@rm -f $(objecst)
