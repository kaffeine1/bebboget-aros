.PHONY: all pre install

LINKME = $(OUTDIR)/libbebboget.a 

ifneq ($(linux),)
AR = ar
CC = gcc
CFLAGS   = -I include -g -DDEBUG=1 -O0 
C++FLAGS = -fno-exceptions -fno-rtti
OUTDIR ?= linux
LIB_EXT = a
#LIBS     = -lstdc++
#LIBS = -static

else
AR = m68k-amigaos-ar
CC = m68k-amigaos-gcc
AS = m68k-amigaos-as

CPU ?= -m68020

ASFLAGS  = -I include
CFLAGS   = -I include -mregparm=3
C++FLAGS = -fno-exceptions -fno-rtti
LDFLAGS  = -noixemul -L $(OUTDIR)
#LDFLAGS += -Wl,-M
LIBS     = 

EXTRA_LIB_SOURCES = socket_glue.c

ifeq ($(CPU),-m68020)
EXTRA_LIB_SOURCES += fastmath-mul32.asm poly.asm edmul32.asm edmul121665-32.asm edsquare32.asm fastmath-all.asm
else
EXTRA_LIB_SOURCES += fastmath-mul16.asm poly16.asm edmul16.asm edmul121665-16.asm edsquare16.asm fastmath-all.asm
endif

ifneq ($(Profile),)
OUTDIR ?= Profile
CFLAGS += -Os -m68020 -DPROFILE -fprofile-dir=/tmp -pg
LIBS += -lgcov
LIB_EXT = a
else
ifneq ($(Release),)
OUTDIR ?= Release
CFLAGS += -Os -fomit-frame-pointer $(CPU)
LDFLAGS += $(STRIP)
# LDFLAGS += -fbaserel32
ifeq ($(STRIP),)
LDFLAGS += -Wl,-u___checkstack 
endif
LIB_EXT = library
else
OUTDIR ?= Debug
LDFLAGS += -g -Wl,-u___checkstack 
#CFLAGS += -O2 -DDEBUG=1 -fomit-frame-pointer $(CPU)
CFLAGS += -Os -DDEBUG=1 $(CPU) -fomit-frame-pointer -fno-move-loop-invariants -fno-tree-loop-im
LIB_EXT = a

# CFLAGS += -flto
# LINKME = $(LIB_OBJECTS)
endif
endif 
endif
 
TARGETS   = bebboget
TPROGRAMS = $(patsubst %,$(OUTDIR)/%,$(TARGETS))
 
LIB_SOURCES = $(EXTRA_LIB_SOURCES) bg.cpp \
	biginteger.cpp unhexlify.c equals.cpp dump.c\
	stream.cpp socket.cpp \
	vector.cpp c++support.cpp \
	chacha20.cpp poly1305.cpp chacha20poly1305.cpp \
	md.cpp sha256.cpp sha384512.cpp sha512.cpp sha384.cpp sha.cpp md5.cpp bc.cpp \
	aes.cpp rc4.cpp des.cpp des3.cpp gcm.cpp \
	rand.cpp log.c mimedecode.c certstuff.cpp\
	x25519.cpp \
	pkcs6.cpp ecmath.cpp fastmath.cpp asn1.cpp secpXXXr1.cpp \
	ssl3.cpp ssl3client.cpp
# secpXXXr2.cpp	

LIB_OBJECTS = $(patsubst %.asm,$(OUTDIR)/%.o, $(patsubst %.cpp,$(OUTDIR)/%.o, $(patsubst %.c,$(OUTDIR)/%.o,$(LIB_SOURCES))))

BEBBOGET_SOURCES = bebboget.cpp 
BEBBOGET_OBJECTS = $(patsubst %.cpp,$(OUTDIR)/%.o, $(patsubst %.c,$(OUTDIR)/%.o,$(BEBBOGET_SOURCES)))

installcerts_SOURCES = installcerts.cpp 
installcerts_OBJECTS = $(patsubst %.cpp,$(OUTDIR)/%.o, $(patsubst %.c,$(OUTDIR)/%.o,$(installcerts_SOURCES)))

T_SOURCES = testSHA256.cpp testSHA512.cpp testSHA.cpp testMD5.cpp 
T_OBJECTS = $(patsubst %.cpp,$(OUTDIR)/%.o, $(patsubst %.c,$(OUTDIR)/%.o,$(T_SOURCES)))

ASMSOURCES = $(wildcard src/*.asm)
ASMOBJECTS = $(patsubst src/%.asm,$(OUTDIR)/%.o,$(ASMSOURCES))
C++SOURCES = $(wildcard src/*.cpp)
C++OBJECTS = $(patsubst src/%.cpp,$(OUTDIR)/%.o,$(C++SOURCES))
TOBJECTS   = $(filter $(OUTDIR)/test%,$(C++OBJECTS)) 
TESTS      = $(patsubst %.o,%,$(TOBJECTS))

HEADERS = $(shell find 2>/dev/null include -type f)

all: pre $(OUTDIR)/libbebboget.a $(OUTDIR)/bebboget $(OUTDIR)/installcerts
	echo $(TESTS) $(TPROGRAMS)
	$(MAKE) $(TESTS) $(TPROGRAMS)

pre: 
	echo $(LIB_OBJECTS)
	mkdir -p $(OUTDIR)

$(OUTDIR)/bebboget: $(BEBBOGET_OBJECTS) $(TESTS) $(OUTDIR)/libbebboget.a
	$(CC) $(CFLAGS) $(C++FLAGS) $(LDFLAGS) $(filter-out $(OUTDIR)/test%,$(filter-out %.$(LIB_EXT),$^)) $(LINKME) $(LIBS) -o $@

$(OUTDIR)/installcerts: $(installcerts_OBJECTS) $(TESTS) $(OUTDIR)/libbebboget.a
	$(CC) $(CFLAGS) $(C++FLAGS) $(LDFLAGS) $(filter-out $(OUTDIR)/test%,$(filter-out %.$(LIB_EXT),$^)) $(LINKME) $(LIBS) -o $@

$(OUTDIR)/libbebboget.a: $(LIB_OBJECTS) 
	$(AR) rcs $@ $^

ifneq (,$(TESTS))
$(TESTS): $(TOBJECTS) Makefile $(OUTDIR)/libbebboget.a 
	$(CC) $(LDFLAGS) $(CFLAGS) $(C++FLAGS) $(patsubst $(OUTDIR)/%,src/%.cpp,$@) $(LINKME) $(LIBS) -o $@
ifeq ($(linux),)
	cd $(OUTDIR); vamos -s40 -C20 -v -- $(patsubst $(OUTDIR)/%,%,$@)
else
	-cd $(OUTDIR); ./$(patsubst $(OUTDIR)/%,%,$@)
endif	
endif

$(OUTDIR)/%.o: src/%.asm Makefile $(HEADERS)
	$(AS) $(CPU) $(ASFLAGS) $< -o $@


$(OUTDIR)/%.o: src/%.cpp Makefile $(HEADERS)
#	$(CC) -c $(LDFLAGS) $(CFLAGS) $(C++FLAGS) $< -S
	$(CC) -c $(LDFLAGS) $(CFLAGS) $(C++FLAGS) $< -o $@

ifeq ($(linux),)
$(OUTDIR)/aes.o: src/aes.cpp Makefile $(HEADERS)
	$(CC) -c $(LDFLAGS) $(CFLAGS) $(C++FLAGS) $< -o $@ -O3

$(OUTDIR)/gcm.o: src/gcm.cpp Makefile $(HEADERS)
	$(CC) -c $(LDFLAGS) $(CFLAGS) $(C++FLAGS) $< -o $@ -O3

$(OUTDIR)/chacha20.o: src/chacha20.cpp Makefile $(HEADERS)
	$(CC) -c $(LDFLAGS) $(CFLAGS) $(C++FLAGS) $< -o $@ -O3

$(OUTDIR)/biginteger.o: src/biginteger.cpp Makefile $(HEADERS)
	$(CC) -c $(LDFLAGS) $(CFLAGS) $(C++FLAGS) $< -o $@ -O3

$(OUTDIR)/fastmath.o: src/fastmath.cpp Makefile $(HEADERS)
	$(CC) -c $(LDFLAGS) $(CFLAGS) $(C++FLAGS) $< -o $@ -O3
endif
 
$(OUTDIR)/%.o: src/%.c Makefile $(HEADERS)
	$(CC) -c $(LDFLAGS) $(CFLAGS) $< -o $@

clean:
	rm -rf $(OUTDIR)/*

install: all
ifneq ($(DEST),)
ifeq ($(linux),)
#	cp $(OUTDIR)/bebboget $(DEST)
	m68k-amigaos-strip $(OUTDIR)/bebboget -o $(DEST)/bebboget
	m68k-amigaos-strip $(OUTDIR)/installcerts -o $(DEST)/installcerts
	
ifeq ($(CPU),-m68020)
	mkdir -p /opt/amiga/lib/libm020
	cp $(OUTDIR)/libbebboget.a /opt/amiga/lib/libm020
else
	cp $(OUTDIR)/libbebboget.a /opt/amiga/lib
endif	
endif
endif
	
tst: src/dump.c src/testFastMath32.cpp src/vector.cpp src/fastmath.cpp src/unhexlify.c src/equals.cpp
	echo gcc -g -I include -o tst $^
	gcc -g -I include -o tst $^ -lstdc++
