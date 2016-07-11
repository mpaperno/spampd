#!/usr/bin/make -f $0
#
# Make file for spampd
# created for the debian project
# by Sven Mueller <debian@incase.de>
# published under the GPL
#
ETCDIR:=$(DESTDIR)/etc
BINDIR:=$(DESTDIR)/usr/sbin
INITDIR:=/etc/init.d
DOCDIR:=$(DESTDIR)/usr/share/doc/spampd
#RUNLEVELDIRS:=$(DESTDIR)/etc/rc3.d
MANDIR:=$(DESTDIR)/usr/share/man
INSTALL:="/usr/bin/install"
LN:="ln"

.PHONY: all install uninstall clean
all: spampd.8.gz spampd.html

install: spampd.8.gz spampd.html
	$(INSTALL) -D -m 755 spampd ${BINDIR}/spampd
	$(INSTALL) -D -m 644 spampd.default ${ETCDIR}/default/spampd	
	$(INSTALL) -D -m 755 spampd-init.sh $(DESTDIR)${INITDIR}/spampd
	$(INSTALL) -D -m 644 spampd.html ${DOCDIR}/spampd.html
	$(INSTALL) -D -m 644 changelog.txt ${DOCDIR}/changelog
	for i in ${RUNLEVELDIRS}; do \
		$(LN) -sf ${INITDIR}/spampd $i/S20spampd ; \
	done
	$(INSTALL) -D -m 644 spampd.8.gz ${MANDIR}/man8/spampd.8.gz

uninstall:
	rm -f ${BINDIR}/spampd
	rm -f ${ETCDIR}/default/spampd
	rm -f $(DESTDIR)${INITDIR}/spampd
	rm -f ${DOCDIR}/spampd.html
	rm -f ${DOCDIR}/changelog
	rmdir ${DOCDIR} || true
	for i in ${RUNLEVELDIRS}; do \
		rm -f $i/S20spampd ; \
	done
	rm -f ${MANDIR}/man8/spampd.8.gz

spampd.8.gz: spampd.8
	gzip -9 < spampd.8 > spampd.8.gz

spampd.8: spampd
	pod2man --section=8 --center="Spam Proxy Daemon" spampd > spampd.8

spampd.html: spampd
	pod2html --outfile spampd.html --header --norecurse --backlink '[Back to top]' --infile spampd
	rm -f pod2htm?.tmp

clean:
	rm -f spampd.8.gz
	rm -f spampd.8
	rm -f spampd.html
