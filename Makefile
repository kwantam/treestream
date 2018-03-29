LDLIBS := -lcrypto++
CXXFLAGS := -m64 -pedantic -pedantic-errors -std=c++11 -Werror -Wall -Wextra -Wshadow -Wpointer-arith -Wcast-qual -Wformat=2 -Weffc++ -O3 -flto

all: treestream

clean:
	@rm -f treestream
