CC = g++
CFLAGS  = -Wall -pedantic -Wextra
TARGET = flow
LIBS = -lpcap
 
all: $(TARGET)
 
$(TARGET): $(TARGET).cpp
	$(CC) $(CFLAGS) $(TARGET).cpp -o $(TARGET) $(LIBS)
