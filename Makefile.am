## Process this file with automake to produce Makefile.in
#
# Makefile.am
#

AM_CPPFLAGS = \
        -DAGENTXD_SYSCONFDIR='"$(sysconfdir)/smartmontools"' \
        -I $(top_srcdir)/include \
        -I $(top_srcdir)/src

sbin_PROGRAMS = smartmon-snmp-agentxd

smartmon_snmp_agentxd_SOURCES = \
        src/agentxd_main.cpp    \
        src/agentxd_config.cpp  \
        src/agentxd_config.h    \
        src/agentxd_datasrc.cpp \
        src/agentxd_datasrc.h   \
        src/agentxd_json.cpp    \
        src/agentxd_json.h      \
        src/agentxd_loop.cpp    \
        src/agentxd_loop.h      \
        src/agentxd_cache.cpp   \
        src/agentxd_cache.h     \
        src/agentxd_notify.cpp  \
        src/agentxd_notify.h    \
        src/snmp_oids.h         \
        src/snmp_mib_helpers.h  \
        src/snmp_common_mib.cpp \
        src/snmp_common_mib.h   \
        src/snmp_nvme_mib.cpp   \
        src/snmp_nvme_mib.h     \
        src/snmp_sata_mib.cpp   \
        src/snmp_sata_mib.h     \
        src/snmp_sas_mib.cpp    \
        src/snmp_sas_mib.h      \
        src/snmp_sensor_mib.cpp \
        src/snmp_sensor_mib.h

smartmon_snmp_agentxd_LDADD = \
        $(top_builddir)/lib/libsmartmon.la \
        $(SNMP_LIBS)

smartmon_snmp_agentxd_DEPENDENCIES = \
        $(top_builddir)/lib/libsmartmon.la

# Sample config file
smartmonconfdir = $(sysconfdir)/smartmontools
dist_smartmonconf_DATA = etc/smartmon-snmp-agentxd.conf

# Man page
man8_MANS = man/smartmon-snmp-agentxd.8

EXTRA_DIST = \
        man/smartmon-snmp-agentxd.8.in \
        systemd/smartmon-snmp-agentxd.service.in \
        systemd/smartmon-collect.service \
        systemd/smartmon-collect.timer \
        bin/smartmon-collect

# Generate man page from .in template
man/smartmon-snmp-agentxd.8: man/smartmon-snmp-agentxd.8.in
	$(AM_V_GEN)sed \
	    -e 's|@sysconfdir@|$(sysconfdir)|g' \
	    -e 's|@sbindir@|$(sbindir)|g' \
	    -e 's|@PACKAGE_VERSION@|$(PACKAGE_VERSION)|g' \
	    $< > $@

# systemd unit (optional — only installed when systemd support is present)
if INSTALL_SYSTEMDUNIT
systemdsystemunit_DATA = smartmon-snmp-agentxd.service

smartmon-snmp-agentxd.service: systemd/smartmon-snmp-agentxd.service.in
	$(AM_V_GEN)sed \
	    -e 's|@sbindir@|$(sbindir)|g' \
	    -e 's|@sysconfdir@|$(sysconfdir)|g' \
	    $< > $@

CLEANFILES = man/smartmon-snmp-agentxd.8 smartmon-snmp-agentxd.service
else
CLEANFILES = man/smartmon-snmp-agentxd.8
endif
