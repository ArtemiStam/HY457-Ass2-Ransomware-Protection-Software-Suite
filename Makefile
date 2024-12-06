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
KEY = 10
SHARES = $(if $(strip $(SHARES)),)

all: antivirus

antivirus: antivirus.o scanner.o inspector.o monitor.o secret_sharing.o
	$(CC) $(CFLAGS) $^ -lcrypto -lcurl -lm -o antivirus

scan:
	./antivirus scan /home/artemi/hy457/assignment2/test_files/

inspect:
	./antivirus inspect /home/artemi/hy457/assignment2/test_files/

monitor:
	./antivirus monitor /home/artemi/hy457/assignment2/test_files/

slice:
	./antivirus slice $(KEY)

unlock: 
	./antivirus unlock $(SHARES)

%.o:%.c
	$(CC) $(CFLAGS) -o $@ -c $<

clean:
	-rm -f antivirus *.o