CXX=gcc

CXXFLAGS=-Wall

LIBRARIES=-lcapstone

sword: sword.o
	$(CXX) $(CXXFLAGS) sword.o $(LIBRARIES) -o sword

sword.o: sword.c
	$(CXX) $(CXXFLAGS) -c sword.c

clean:
	-rm -f sword *.o
