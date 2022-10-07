SPATH = .
EXCLUDE_FILE := 
SOURCES = $(foreach dir, $(SPATH), $(wildcard $(dir)/*.c))
SOURCES := $(filter-out $(EXCLUDE_FILE), $(SOURCES))
OBJS = $(SOURCES:%.c=%.o)

TOOL_PREFIX = 
COMPILE_TOOLS = $(TOOL_PREFIX)gcc
AR = $(TOOL_PREFIX)ar
OBJ = $(TOOL_PREFIX)objdump

CFLAGS := -Wall -Werror

LIBCFLAGS := -shared

BIN = demo
LIB = lib$(BIN).a
SO = lib$(BIN).so 

all : $(BIN) lib
lib : $(LIB) $(SO)

$(LIB) : $(OBJS)
	@$(AR) cr $@ $^

$(SO) : $(OBJS)
	@$(COMPILE_TOOLS) -o $@ $^ $(CFLAGS) $(LIBCFLAGS)

$(BIN):$(OBJS)
	$(COMPILE_TOOLS) -o $@ $^ $(CFLAGS)
	# $(OBJ) $(BIN) -dS > $(BIN).S

%.o:%.c
	$(COMPILE_TOOLS) $(CFLAGS) -c $^ -o $@

.PHONY:clean
clean:
	-rm -rf *.o $(BIN) *.S *.so *.a
