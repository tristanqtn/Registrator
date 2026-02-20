# ==============================================================================
# Registrator - Makefile
# ==============================================================================
#
# Targets:
#   make              - Build the binary (default)
#   make clean        - Remove build artifacts
#   make release      - Build a fully static, stripped binary
#   make check        - Verify no unexpected DLL dependencies (requires objdump)
#
# Cross-compilation from Linux:
#   make CC=x86_64-w64-mingw32-gcc
#   make release CC=x86_64-w64-mingw32-gcc
# ==============================================================================

# --- Toolchain ----------------------------------------------------------------

CC      = gcc
OBJDUMP = objdump

# If cross-compiling, derive objdump from the CC prefix automatically
# e.g. CC=x86_64-w64-mingw32-gcc → OBJDUMP=x86_64-w64-mingw32-objdump
ifneq ($(findstring mingw32, $(CC)),)
    OBJDUMP = $(subst gcc,objdump,$(CC))
endif

# --- Paths --------------------------------------------------------------------

SRC_DIRS  = src/core src/utils
INC_DIR   = include
BUILD_DIR = build
OUT       = registrator.exe

# --- Sources & Objects --------------------------------------------------------

SRCS = $(wildcard $(addsuffix /*.c, $(SRC_DIRS)))
OBJS = $(patsubst src/%.c, $(BUILD_DIR)/%.o, $(SRCS))

# --- Flags --------------------------------------------------------------------

CFLAGS   = -Wall -Wextra -O2 -I $(INC_DIR)
LDFLAGS  = -ladvapi32

# Static flags used by the 'release' target only
STATIC_FLAGS = -static -static-libgcc -static-libstdc++

# --- Rules --------------------------------------------------------------------

.PHONY: all release clean check

all: $(OUT)

## Link
$(OUT): $(OBJS)
	$(CC) $(OBJS) $(LDFLAGS) -o $@
	@echo "[+] Build complete: $@"

## Compile — mirror src/ subdirectory structure inside build/
$(BUILD_DIR)/%.o: src/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

## Static release build — single self-contained executable, stripped of debug symbols
release: LDFLAGS += $(STATIC_FLAGS) -s
release: clean $(OUT)
	@echo "[+] Release build complete: $(OUT)"

## Remove all build artifacts
clean:
	rm -rf $(BUILD_DIR) $(OUT)
	@echo "[i] Cleaned build artifacts"

## Verify DLL dependencies — only system DLLs should appear
check: $(OUT)
	@echo "[i] DLL dependencies for $(OUT):"
	@$(OBJDUMP) -p $(OUT) | grep "DLL Name"