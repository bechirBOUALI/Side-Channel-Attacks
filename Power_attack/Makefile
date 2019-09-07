# MASTER-ONLY: DO NOT MODIFY THIS FILE

#
# Copyright (C) Telecom ParisTech
# 
# This file must be used under the terms of the CeCILL. This source
# file is licensed as described in the file COPYING, which you should
# have received as part of this distribution. The terms are also
# available at:
# http://www.cecill.info/licences/Licence_CeCILL_V1.1-US.txt
#

SHELL		:= /bin/bash

CC		:= gcc
CFLAGS		:= -Wall -c -O3
INCLUDES	:= -I.
LD		:= gcc
LDFLAGS		:=
LIBS		:= -lm
LANGUAGE	:= $(wildcard .c)$(wildcard .py)
ifeq ($(LANGUAGE),.py)
PYCFLAGS	:= -std=c99 -fPIC $(shell python-config --cflags)
PYLDFLAGS	:= -shared -fPIC $(shell python-config --ldflags)
endif

OBJS		:= $(patsubst %.c,%.o,$(wildcard *.c))
PYSOS		:= des.so km.so
PYCS		:= $(patsubst %.py,%.pyc,$(wildcard *.py))
PYOBJS		:= $(patsubst %.c,PyC_%.o,$(wildcard *.c))

DATA		:= pa.hws
KEY		:= pa.key
EXTRADATA	:= average.cmd average.dat dpa.cmd dpa.dat

.PHONY: help all clean check

define HELP_message
Usage: make [GOAL]

goals:
	help		print this message
	all		build everything
	check		check the compliance of your code with specifications
	clean		to clean
endef
export HELP_message

help::
	@printf '%s\n' "$$HELP_message"

pa: pa.o des.o km.o utils.o traces.o tr_pcc.o
des.so: Py_des.o PyC_des.o PyC_utils.o
km.so: Py_km.o PyC_km.o PyC_utils.o PyC_des.o

pa $(PYSOS):
	$(LD) $(LDFLAGS) $^ -o $@ $(LIBS)

Py_%.o PyC_%.o: CFLAGS += $(PYCFLAGS)
PyC_utils.o: CFLAGS += -DPYTHON_LIB 
$(PYSOS): LDFLAGS += $(PYLDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) $(INCLUDES) $< -o $@

PyC_%.o: %.c
	$(CC) $(CFLAGS) $(INCLUDES) $< -o $@

ifeq ($(LANGUAGE),)

check all:
	$(error 'Language file not found. Please create the .c or .py file.')

else ifeq ($(LANGUAGE),.c.py)

check all:
	$(error 'Both language files found. Please delete the .c or .py file.')

else

SRC	:= pa$(LANGUAGE)
EXEC	:= $(patsubst pa.c,pa,$(SRC))

ifeq ($(LANGUAGE),.py)

check all: $(PYSOS) $(EXEC)

else

check all: $(EXEC)

endif

check:
	@source $(KEY) && \
	k16ref=$$k16 && \
	printf '\n%s\n' "# Attack:" && \
	printf '%s\n' "./$(EXEC) $(DATA) 1000" && \
	k16=$$( ./$(EXEC) $(DATA) 1000 2> /dev/null ) && \
	printf '%s\n' "$$k16" && \
	if [ -z "$$k16" ]; then \
		printf '%s\n' "***** FAILED (no output) *****" && \
		exit 1; \
	elif [[ ! "$$k16" =~ ^0x[0-9a-fA-F]{12}$$ ]]; then \
		printf '%s\n' "***** FAILED (invalid output $$k16) *****" && \
		exit 1; \
	fi && \
	printf '\n%s\n' "# Check:" && \
	printf '%s\n' "OK, you can now push your work" && \
	if [[ "$${k16,,}" != "$${k16ref,,}" ]]; then \
		printf '\n%s\n' "# Note:" && \
		printf '%s\n' "Even if your attack fails ($$k16 != $$k16ref)" && \
		printf '%s\n' "with 1000 acquisitions, it may work with more..."; \
	fi

endif

clean::
	rm -f $(OBJS) $(PYSOS) $(PYCS) $(PYOBJS) $(EXTRADATA) pa

