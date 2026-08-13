# ===== Werkzeuge =====
CC      := cc
CFLAGS  := -std=c11 -Wall -Wextra -Wpedantic -g -O0
LDFLAGS := -lcurl

# ===== Dateien =====
TARGET := van
SRC    := main.c cJSON.c claude.c sqlite3.c utils.c db.c cmd.c
OBJ    := $(SRC:.c=.o)

# ===== Standard-Regeln =====
.PHONY: all clean run

all: $(TARGET)

sqlite3.o: sqlite3.c sqlite3.h
	$(CC) -O2 -c -o $@ $<

# Linken
$(TARGET): $(OBJ)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

# Kompilieren (implizite Regel reicht, hier nur für Flags)
%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

# Programm direkt bauen und ausführen
run: $(TARGET)
	./$(TARGET) $(ARGS)

# Aufräumen
clean:
	rm -f $(filter-out sqlite3.o,$(OBJ)) $(TARGET)
