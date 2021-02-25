
main:main.o clickhouse.o
	g++ main.o clickhouse.o -o pcapAna -L /opt/sniffcatch/pcapPrase/clickhouse-cpp-master/build/clickhouse -lclickhouse-cpp-lib -lpcap  -std=c++17 -I  ./ -I /opt/sniffcatch/pcapPrase/clickhouse-cpp-master -O3

main.o: main.cpp
	g++ -c main.cpp -o main.o  -I ./  -I /opt/sniffcatch/pcapPrase/clickhouse-cpp-master -std=c++17 -L /opt/sniffcatch/pcapPrase/clickhouse-cpp-master/build/clickhouse -lclickhouse-cpp-lib

clickhouse.o:clickhouse.cpp clickhouse.h
	g++ -c clickhouse.cpp -o  clickhouse.o -I ./ -I /opt/sniffcatch/pcapPrase/clickhouse-cpp-master -std=c++17  -L /opt/sniffcatch/pcapPrase/clickhouse-cpp-master/build/clickhouse -lclickhouse-cpp-lib