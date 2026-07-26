# Makefile — SM3 密码杂凑算法 SIMD 优化实现
#
# 用法:  mingw32-make          编译并运行测试
#        mingw32-make clean     清理构建产物
#        mingw32-make help      显示帮助

# 编译器 
CC       = gcc
AR       = ar
RM       = rm -f

# ARM64 交叉编译器
CC_ARM64 = aarch64-linux-gnu-gcc

CFLAGS      = -Wall -Wextra -O3 -std=c99
CFLAGS_AVX2 = -mavx2 -mfma -D__AVX2__
CFLAGS_NEON = -march=armv8-a+simd -D__ARM_NEON
LDFLAGS     = -lm

SRC_REF   = sm3_ref.c
SRC_AVX2  = sm3_avx2.c
SRC_NEON  = sm3_neon.c
SRC_TEST  = sm3_test.c

OBJ_REF    = build/sm3_ref.o
OBJ_AVX2   = build/sm3_avx2.o
OBJ_NEON   = build/sm3_neon.o
OBJ_TEST   = build/sm3_test.o
OBJ_ARM_REF  = build_arm64/sm3_ref.o
OBJ_ARM_NEON = build_arm64/sm3_neon.o

BIN_TEST  = build/sm3_test.exe
LIB_REF   = build/libsm3.a
BIN_ARM64 = build_arm64/sm3_test_arm64


.PHONY: all
all: test
	@echo ============================================
	@echo   Build complete. Running tests...
	@echo ============================================
	@./$(BIN_TEST)

.PHONY: x86
x86: $(BIN_TEST)
	@echo [OK] x86 build complete: $(BIN_TEST)

.PHONY: test
test: $(BIN_TEST)
	@echo [OK] Test binary ready.

$(BIN_TEST): $(OBJ_REF) $(OBJ_AVX2) $(OBJ_TEST)
	$(CC) $(CFLAGS) $(CFLAGS_AVX2) -o $@ $^ $(LDFLAGS)
	@echo [LD] $@

$(OBJ_REF): $(SRC_REF) sm3.h
	-mkdir build
	$(CC) $(CFLAGS) -c -o $@ $(SRC_REF)
	@echo [CC] $@ [scalar]

$(OBJ_AVX2): $(SRC_AVX2) sm3.h
	-mkdir build
	$(CC) $(CFLAGS) $(CFLAGS_AVX2) -c -o $@ $(SRC_AVX2)
	@echo [CC] $@ [AVX2 SIMD]

$(OBJ_TEST): $(SRC_TEST) sm3.h
	-mkdir build
	$(CC) $(CFLAGS) $(CFLAGS_AVX2) -c -o $@ $(SRC_TEST)
	@echo [CC] $@ [test]

.PHONY: ref
ref: $(OBJ_REF)
	-mkdir build
	$(CC) $(CFLAGS) -o build/sm3_ref_test.exe $(SRC_REF) $(SRC_TEST) \
		-DSM3_REF_ONLY $(LDFLAGS)
	@echo [OK] Reference-only build: build/sm3_ref_test.exe

.PHONY: arm64
arm64: $(BIN_ARM64)
	@echo [OK] ARM64 cross-compile complete: $(BIN_ARM64)

$(BIN_ARM64): $(OBJ_ARM_REF) $(OBJ_ARM_NEON)
	$(CC_ARM64) $(CFLAGS) $(CFLAGS_NEON) -o $@ \
		$(OBJ_ARM_REF) $(OBJ_ARM_NEON) $(SRC_TEST) $(LDFLAGS)
	@echo [LD] $@

$(OBJ_ARM_REF): $(SRC_REF) sm3.h
	-mkdir build_arm64
	$(CC_ARM64) $(CFLAGS) -c -o $@ $(SRC_REF)
	@echo [CC-ARM64] $@ [scalar]

$(OBJ_ARM_NEON): $(SRC_NEON) sm3.h
	-mkdir build_arm64
	$(CC_ARM64) $(CFLAGS) $(CFLAGS_NEON) -c -o $@ $(SRC_NEON)
	@echo [CC-ARM64] $@ [NEON SIMD]

.PHONY: lib
lib: $(LIB_REF)

$(LIB_REF): $(OBJ_REF) $(OBJ_AVX2)
	$(AR) rcs $@ $^
	@echo [AR] $@


.PHONY: clean
clean:
	-$(RM) -r build build_arm64
	@echo [CLEAN] Done.

.PHONY: help
help:
	@echo SM3 Hash Algorithm - Build System
	@echo.
	@echo Targets:
	@echo   mingw32-make          Build and run all tests
	@echo   mingw32-make x86      Build x86 only (scalar + AVX2)
	@echo   mingw32-make arm64    Cross-compile ARM64 (NEON)
	@echo   mingw32-make ref      Build reference-only version
	@echo   mingw32-make lib      Build static library
	@echo   mingw32-make clean    Remove build artifacts
	@echo   mingw32-make help     Show this help
