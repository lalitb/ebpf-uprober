BPF_CLANG ?= clang
BPF_LLVM_STRIP ?= llvm-strip
BPF_CFLAGS = -g -O2 -target bpf -D__TARGET_ARCH_x86
LIBBPF_OBJ_DIR = /usr/lib/libbpf.a

BPF_DIR = bpf
SRC_DIR = src
TARGET = target
BPF_OBJ = $(BPF_DIR)/uprober.bpf.o

# Default target
all: build

# Compile the eBPF program
$(BPF_OBJ): $(BPF_DIR)/uprober.bpf.c
	$(BPF_CLANG) $(BPF_CFLAGS) -c $< -o $@
	$(BPF_LLVM_STRIP) -g $@

# Build Rust project with libbpf bindings
build: $(BPF_OBJ)
	cargo build --release

# Run with sudo
run: build
	sudo $(TARGET)/release/uprober

# Clean build files
clean:
	cargo clean
	rm -f $(BPF_OBJ)

.PHONY: all build run clean
