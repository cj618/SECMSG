\
PREFIX?=/usr/local
BINDIR?=$(PREFIX)/bin
LIBDIR?=$(PREFIX)/lib/secmsg

PERL?=perl
PERL5LIB?=lib

all:
	@echo "Targets: test run-server run-client install"

test:
	$(PERL) -I$(PERL5LIB) -c bin/secmsg
	$(PERL) -I$(PERL5LIB) -c bin/secmsgd
	$(PERL) -I$(PERL5LIB) -c lib/SecMsg.pm

run-server:
	$(PERL) -I$(PERL5LIB) bin/secmsgd -l 127.0.0.1 -p 7337

run-client:
	$(PERL) -I$(PERL5LIB) bin/secmsg -s 127.0.0.1:7337 -u alice

install:
	install -d $(DESTDIR)$(BINDIR) $(DESTDIR)$(LIBDIR)
	install -m 0755 bin/secmsg bin/secmsgd $(DESTDIR)$(BINDIR)/
	install -m 0644 lib/SecMsg.pm $(DESTDIR)$(LIBDIR)/
