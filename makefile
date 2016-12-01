CXX 		= g++
CXXFLAGS 	= -Wall -std=c++11
TARGET 		= program

LIBS		= -lpthread

INC_DIR		= include external/ArgvParser
SRC_DIR 	= src
OBJ_DIR 	= obj
BIN_DIR 	= build

SOURCES 	= $(wildcard $(SRC_DIR)/*.cpp $(SRC_DIR)/*.c)
HEADERS		= $(wildcard $(SRC_DIR)/*.hpp $(SRC_DIR)/*.h)
OBJECTS 	= $(patsubst $(SRC_DIR)/%.cpp, $(OBJ_DIR)/%.o, $(SOURCES))

ARG_OBJ		= external/ArgvParser/argvparser.o
ARG_INC		= external/ArgvParser/argvparser.h
HEADERS		+= $(ARG_INC)

INC_FLAG 	= $(patsubst %, -I %, $(INC_DIR))

EXECUTABLE 	= $(BIN_DIR)/$(TARGET)

.PHONY : all clean

all : $(TARGET)

$(TARGET) : $(EXECUTABLE)

$(EXECUTABLE) : $(OBJECTS)
	$(MAKE) -C external/ArgvParser
	$(CXX) $(CXXFLAGS) $(OBJECTS) $(ARG_OBJ) $(INC_FLAG) $(LIBS) -o $(EXECUTABLE)

$(OBJ_DIR)/%.o : $(SRC_DIR)/%.cpp $(HEADERS)
	mkdir -p $(OBJ_DIR)
	$(CXX) $(CXXFLAGS) -c -o $@ $< $(INC_FLAG)

clean:
	$(MAKE) -C external/ArgvParser clean
	rm -rf obj
	rm $(EXECUTABLE)
