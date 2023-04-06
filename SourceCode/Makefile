# Makefile文件

# 编译器
CC=gcc

# 编译选项
CFLAGS=-Wall -Wextra

# 目标文件
TARGET=azm

# 源文件
SRC=azmanager.c

# 默认目标
all: $(TARGET)

# 编译目标
$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC)

# 清理目标
clean:
	rm -f $(TARGET)

.PHONY: all clean
