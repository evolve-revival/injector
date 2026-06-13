CC      = x86_64-w64-mingw32-gcc
CFLAGS  = -O2 -Wall -shared
TARGET  = dbghelp.dll

$(TARGET): dbghelp.c dbghelp.def
	$(CC) $(CFLAGS) -o $(TARGET) dbghelp.c dbghelp.def

clean:
	rm -f $(TARGET)
