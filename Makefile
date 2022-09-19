PROJECT = erl_modsec
PROJECT_DESCRIPTION = New project
PROJECT_VERSION = 0.1.0

# For modsecurity that wasn't installed via package manager
CFLAGS += -I"/usr/local/modsecurity/include"
LDLIBS += /usr/local/modsecurity/lib/libmodsecurity.so.3

include erlang.mk
