# Build the BSGS scanner. OpenSSL is found via pkg-config, else Homebrew.
CFLAGS ?= -O3
PKG := $(shell pkg-config --exists openssl && echo yes)
ifeq ($(PKG),yes)
  SSL_CFLAGS := $(shell pkg-config --cflags openssl)
  SSL_LIBS := $(shell pkg-config --libs openssl)
else
  BREW := $(shell for f in openssl@4 openssl@3 openssl; do brew --prefix $$f 2>/dev/null && break; done)
  SSL_CFLAGS := -I$(BREW)/include
  SSL_LIBS := -L$(BREW)/lib -lcrypto
endif

bsgs: bsgs.c
	$(CC) $(CFLAGS) -o $@ $< $(SSL_CFLAGS) $(SSL_LIBS) -lpthread

clean:
	rm -f bsgs
.PHONY: clean
