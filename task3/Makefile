CXX = g++
CXXFLAGS = -std=c++17 -O3 -Wall -Wextra -Wno-parentheses -Wno-unused-variable -msse4.1 -mssse3 -maes -mpclmul

LDFLAGS =

AES_SRCS = aes_ni.cpp aes_ttable.cpp
SM4_SRCS = sm4_basic.cpp sm4_ttable.cpp sm4_shuffle.cpp
GIFT_SRCS = gift_basic.cpp gift_bitslice.cpp gift_shuffle.cpp
TWINE_SRCS = twine_basic.cpp twine_ttable.cpp twine_shuffle.cpp
MODE_SRCS = ctr.cpp gcm.cpp xts.cpp gf128.cpp
TEST_SRCS = test.cpp
BENCH_SRCS = bench.cpp

AES_OBJS = $(AES_SRCS:.cpp=.o)
SM4_OBJS = $(SM4_SRCS:.cpp=.o)
GIFT_OBJS = $(GIFT_SRCS:.cpp=.o)
TWINE_OBJS = $(TWINE_SRCS:.cpp=.o)
MODE_OBJS = $(MODE_SRCS:.cpp=.o)
TEST_OBJ = $(TEST_SRCS:.cpp=.o)
BENCH_OBJ = $(BENCH_SRCS:.cpp=.o)

ALL_OBJS = $(AES_OBJS) $(SM4_OBJS) $(GIFT_OBJS) $(TWINE_OBJS) $(MODE_OBJS)

.PHONY: all test bench run-test run-bench run clean

all: test bench

test: $(ALL_OBJS) $(TEST_OBJ)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

bench: $(ALL_OBJS) $(BENCH_OBJ)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.cpp
	$(CXX) $(CXXFLAGS) -I. -c -o $@ $<

aes_ttable.o: aes_ttable.cpp aes.h
aes_ni.o: aes_ni.cpp aes.h
sm4_basic.o: sm4_basic.cpp sm4.h
sm4_ttable.o: sm4_ttable.cpp sm4.h
sm4_shuffle.o: sm4_shuffle.cpp sm4.h
gift_basic.o: gift_basic.cpp gift.h
gift_bitslice.o: gift_bitslice.cpp gift.h
gift_shuffle.o: gift_shuffle.cpp gift.h
twine_basic.o: twine_basic.cpp twine.h
twine_ttable.o: twine_ttable.cpp twine.h
twine_shuffle.o: twine_shuffle.cpp twine.h
ctr.o: ctr.cpp aes.h sm4.h gift.h twine.h gf128.h
gcm.o: gcm.cpp aes.h sm4.h gift.h twine.h gf128.h
xts.o: xts.cpp aes.h sm4.h gift.h twine.h gf128.h
gf128.o: gf128.cpp gf128.h
test.o: test.cpp aes.h sm4.h gift.h twine.h gf128.h
bench.o: bench.cpp aes.h sm4.h gift.h twine.h gf128.h

run-test: test
	./test

run-bench: bench
	./bench

run: run-test run-bench

clean:
	rm -f *.o test bench test.exe bench.exe
