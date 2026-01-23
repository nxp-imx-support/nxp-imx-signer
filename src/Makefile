#==============================================================================
#    Copyright 2022-2025 NXP
#
#    SPDX-License-Identifier: GPL-2.0-only
#==============================================================================

CC        ?= gcc
CFLAGS    ?= -g -Wall -Werror
CPPFLAGS  ?=
LDFLAGS   ?=
INCLUDES  = -I../inc/

PREFIX   ?= /usr/local
BINDIR   ?= $(PREFIX)/bin
DATADIR  ?= $(PREFIX)/share

SIGNER_NAME = imx_signer

#DEPS = $(SIGNER_NAME).h cfg_parser.h
SRCS = $(SIGNER_NAME).c cfg_parser.c fdt.c
OBJS = $(SRCS:.c=.o)

.PHONY: all install clean

all: $(SIGNER_NAME)

%.o: %.c
	$(CC) -c $(INCLUDES) $(CFLAGS) $(LDFLAGS) $(CPPFLAGS) $< -o $@

$(SIGNER_NAME): $(OBJS)
	$(CC) $(INCLUDES) $(CFLAGS) $(LDFLAGS) $(CPPFLAGS) -o $@ $^

install: $(SIGNER_NAME)
	install -D -m 0755 $(SIGNER_NAME) $(DESTDIR)/$(BINDIR)/$(SIGNER_NAME)
	install -D -m 0755 -t $(DESTDIR)$(DATADIR)/doc/$(SIGNER_NAME) \
            ../csf_ahab.cfg.sample \
            ../csf_hab4.cfg.sample
clean:
	$(RM) $(SIGNER_NAME) *.o
