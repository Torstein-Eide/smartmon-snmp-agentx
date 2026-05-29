CXX ?= g++
PKG_CONFIG ?= pkg-config
NET_SNMP_CONFIG ?= net-snmp-config

PREFIX ?= /usr/local
SYSCONFDIR ?= /etc
SBINDIR ?= $(PREFIX)/sbin
BUILDDIR ?= .build
OBJDIR := $(BUILDDIR)/obj
BINDIR := $(BUILDDIR)
TARGET := $(BINDIR)/smartmon-snmp-agentxd

CPPFLAGS ?=
CXXFLAGS ?= -std=c++17 -O2 -Wall
LDFLAGS ?=
SNMP_AGENT_LIBS := $(shell $(NET_SNMP_CONFIG) --agent-libs 2>/dev/null)

AGENTXD_CPPFLAGS := \
	-DAGENTXD_SYSCONFDIR='"$(SYSCONFDIR)/smartmontools"' \
	-I src

SOURCES := $(sort $(wildcard src/*.cpp))
HEADERS := $(sort $(wildcard src/*.h))
OBJECTS := $(patsubst src/%.cpp,$(OBJDIR)/%.o,$(SOURCES))

.PHONY: all check-deps test clean install

all: $(TARGET)

check-deps:
	@command -v $(CXX) >/dev/null 2>&1 || { echo "ERROR: C++ compiler not found: $(CXX)" >&2; exit 1; }
	@command -v $(NET_SNMP_CONFIG) >/dev/null 2>&1 || { echo "ERROR: net-snmp-config not found. Install libsnmp-dev." >&2; exit 1; }
	@test -n "$(SNMP_AGENT_LIBS)" || { echo "ERROR: net-snmp-config --agent-libs returned no linker flags." >&2; exit 1; }

$(OBJDIR)/%.o: src/%.cpp $(HEADERS) | check-deps
	mkdir -p $(OBJDIR)
	$(CXX) $(CPPFLAGS) $(AGENTXD_CPPFLAGS) $(CXXFLAGS) -c $< -o $@

$(TARGET): $(OBJECTS)
	mkdir -p $(BINDIR)
	$(CXX) $(LDFLAGS) $(OBJECTS) -o $@ $(SNMP_AGENT_LIBS) -lsqlite3 -lsystemd

test:
	$(MAKE) -C tests test

clean:
	rm -rf $(BUILDDIR)
	$(MAKE) -C tests clean

install: $(TARGET)
	install -d $(DESTDIR)$(SBINDIR)
	install -m 755 $(TARGET) $(DESTDIR)$(SBINDIR)/smartmon-snmp-agentxd
