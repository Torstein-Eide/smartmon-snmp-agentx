# Makefile — build and run snmp-agentxd unit + integration tests
# No net-snmp required.  Run: make test FIXTURES=<path-to-fixture-dir>

CXX      ?= g++
CXXFLAGS ?= -std=c++14 -Wall -Wextra -g
SRCDIR   := ../src
REPO_ROOT := $(abspath ..)
FIXTURES ?= $(abspath fixtures)
BUILDDIR ?= $(REPO_ROOT)/.build/snmp-agentxd/tests

DEPDIR   := $(BUILDDIR)/.deps

# Source files shared by tests (no net-snmp dependencies)
COMMON_SRC := $(SRCDIR)/agentxd_json.cpp $(SRCDIR)/agentxd_cache.cpp

TEST_JSON := $(BUILDDIR)/test_json
TEST_DATASRC := $(BUILDDIR)/test_datasrc
TESTS := $(TEST_JSON) $(TEST_DATASRC)

all: $(TESTS)

$(BUILDDIR) $(DEPDIR):
	mkdir -p $@

$(TEST_JSON): test_json.cpp $(SRCDIR)/agentxd_json.cpp | $(BUILDDIR) $(DEPDIR)
	$(CXX) $(CXXFLAGS) -I$(SRCDIR) -MMD -MP -MF $(DEPDIR)/$(@F).d -o $@ $^

DATASRC_DEPS := $(SRCDIR)/agentxd_datasrc.cpp $(SRCDIR)/agentxd_datasrc.h \
                $(SRCDIR)/agentxd_cache.cpp $(SRCDIR)/agentxd_cache.h \
                $(SRCDIR)/agentxd_json.cpp  $(SRCDIR)/agentxd_json.h \
                $(SRCDIR)/agentxd_config.h

$(TEST_DATASRC): test_datasrc.cpp $(DATASRC_DEPS) | $(BUILDDIR) $(DEPDIR)
	$(CXX) $(CXXFLAGS) -I$(SRCDIR) -MMD -MP -MF $(DEPDIR)/$(@F).d -o $@ $<

-include $(DEPDIR)/test_json.d $(DEPDIR)/test_datasrc.d

# Run all tests; pass fixture files if the directory exists
FIXTURE_FILES := $(wildcard $(FIXTURES)/*.json)

test: all
	@echo "=== test_json ==="
	$(TEST_JSON) $(FIXTURE_FILES)
	@echo "=== test_datasrc ==="
	$(TEST_DATASRC) $(FIXTURE_FILES)
	@echo "=== All tests passed ==="

clean:
	rm -rf $(BUILDDIR)

.PHONY: all test clean
