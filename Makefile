###################################################
#
# file: Makefile
#
# @Author:   Artemisia Stamataki
# @Version:  31-03-2024
# @email:    csd4742@csd.uoc.gr
#
# Makefile
#
####################################################

CC = gcc
CFLAGS = -Wall -pedantic 

all: antivirus

antivirus: antivirus.o scanner.o inspector.o monitor.o
	$(CC) $(CFLAGS) $^ -lcrypto -lcurl -o antivirus

scan:
	./antivirus scan /home/artemi/hy457/assignment2/Target/

inspect:
	./antivirus inspect /home/artemi/hy457/assignment2/Target/

monitor:
	./antivirus monitor /home/artemi/hy457/assignment2/folder/

%.o:%.c
	$(CC) $(CFLAGS) -o $@ -c $<

clean:
	-rm -f antivirus *.o