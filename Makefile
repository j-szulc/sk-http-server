SOURCES="main.cpp"
OUT="serwer"
.PHONY : clean

serwer:
	g++ --std=c++17 -Wall -Wextra -O3 -o ${OUT} ${SOURCES} -lstdc++fs

clean:
	rm -f ${OUT} || true
