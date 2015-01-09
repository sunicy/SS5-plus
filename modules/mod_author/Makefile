#
#	ss5 - The "ss5" program.
#	Copyright (C) 2006 Matteo Ricchetti
#
#	This program is free software; you can redistribute it and/or modify
#	it under the terms of the GNU General Public License as published by
#	the Free Software Foundation; either version 2 of the License, or
#	(at your option) any later version.
#
#	This program is distributed in the hope that it will be useful,
#	but WITHOUT ANY WARRANTY; without even the implied warranty of
#	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#	GNU General Public License for more details.
#
#	You should have received a copy of the GNU General Public License
#	along with this program; if not, write to the Free Software
#	Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111, USA.
#
# build/module_top.mk
#

SHELL=/bin/sh
srcdir=.
top_srcdir=../..
top_builddir=../..

CFLAGS=-g -O2 -DLINUX -D_FILE_OFFSET_BITS=64 -I . -I $(top_srcdir)/include -shared -fPIC  

LIBS = -lpthread

CC = gcc
MODULE		= mod_authorization.so
MODULEOBJ	= SS5Mod_authorization.o ../../common/SS5OpenLdap.o ../../common/SS5MySql.o

all:	$(MODULE)

$(MODULE) : $(MODULEOBJ)
	$(CC) $(CFLAGS) -o $(MODULE) $(MODULEOBJ) $(LIBS)

clean:
	rm -f $(MODULEOBJ)
	rm -f $(MODULE)

distclean: clean
	rm -f Makefile
