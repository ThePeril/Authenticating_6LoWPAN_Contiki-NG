CONTIKI_PROJECT = hello-world
PROJECT_SOURCEFILES = hmac.c sha256.c utils.c aes_encrypt.c aes_decrypt.c ccm_mode.c
#MODULES += os/services/simple-energest
all: $(CONTIKI_PROJECT)
CONTIKI = ../../..
include $(CONTIKI)/Makefile.include
