CC     = gcc
CFLAGS = -std=gnu11 -Wall -I include -g

SRC_DIR   = src
BUILD_DIR = build

C_FILES   = $(wildcard $(SRC_DIR)/*c)
OBJ_FILES = $(C_FILES:$(SRC_DIR)/%.c=$(BUILD_DIR)/%.o)

PROGS = ipsec_hijack

all: $(PROGS)

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c
	$(shell [ ! -d $(@D) ] && mkdir -p $(@D)) 
	$(CC) $(CFLAGS) -c $< -o $@

$(PROGS): $(OBJ_FILES)
	$(CC) $(CFLAGS) $^ -o $@

clean:
	rm -rf $(BUILD_DIR) $(PROGS)
