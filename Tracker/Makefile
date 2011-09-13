all: ../o_files/database.o ../o_files/sql_query.o ../o_files/sql_result.o ../o_files/bt_misc.o ../o_files/bvalue.o ../o_files/sha1.o ../o_files/socket.o ../o_files/virtual_binary.o ../o_files/xcc_z.o ../o_files/client.o ../o_files/config.o ../o_files/connection.o ../o_files/epoll.o ../o_files/server.o ../o_files/tcp_listen_socket.o ../o_files/tracker_input.o ../o_files/transaction.o ../o_files/udp_listen_socket.o ../o_files/XBT\ Tracker.o
	g++ -g -DNDEBUG -I ../misc -I . -O3 -o xbt_tracker \
	../o_files/database.o \
	../o_files/sql_query.o \
	../o_files/sql_result.o \
	../o_files/bt_misc.o \
	../o_files/bvalue.o \
	../o_files/sha1.o \
	../o_files/socket.o \
	../o_files/virtual_binary.o \
	../o_files/xcc_z.o \
	../o_files/client.o \
	../o_files/config.o \
	../o_files/connection.o \
	../o_files/epoll.o \
	../o_files/server.o \
	../o_files/tcp_listen_socket.o \
	../o_files/tracker_input.o \
	../o_files/transaction.o \
	../o_files/udp_listen_socket.o \
	"../o_files/XBT Tracker.o" \
	`mysql_config --libs`
	strip xbt_tracker
	
../o_files/database.o: ../misc/sql/database.cpp
	g++ -DNDEBUG -I ../misc -I . -O3 -c -o ../o_files/database.o -g ../misc/sql/database.cpp
	
../o_files/sql_query.o: ../misc/sql/sql_query.cpp
	g++ -DNDEBUG -I ../misc -I . -O3 -c -o ../o_files/sql_query.o -g ../misc/sql/sql_query.cpp
	
../o_files/sql_result.o: ../misc/sql/sql_result.cpp
	g++ -DNDEBUG -I ../misc -I . -O3 -c -o ../o_files/sql_result.o -g ../misc/sql/sql_result.cpp
	
../o_files/bt_misc.o: ../misc/bt_misc.cpp
	g++ -DNDEBUG -I ../misc -I . -O3 -c -o ../o_files/bt_misc.o -g ../misc/bt_misc.cpp

../o_files/bvalue.o: ../misc/bvalue.cpp
	g++ -DNDEBUG -I ../misc -I . -O3 -c -o ../o_files/bvalue.o -g ../misc/bvalue.cpp
	
../o_files/sha1.o: ../misc/sha1.cpp
	g++ -DNDEBUG -I ../misc -I . -O3 -c -o ../o_files/sha1.o -g ../misc/sha1.cpp
	
../o_files/socket.o: ../misc/socket.cpp
	g++ -DNDEBUG -I ../misc -I . -O3 -c -o ../o_files/socket.o -g ../misc/socket.cpp
	
../o_files/virtual_binary.o: ../misc/virtual_binary.cpp
	g++ -DNDEBUG -I ../misc -I . -O3 -c -o ../o_files/virtual_binary.o -g ../misc/virtual_binary.cpp
	
../o_files/xcc_z.o: ../misc/xcc_z.cpp
	g++ -DNDEBUG -I ../misc -I . -O3 -c -o ../o_files/xcc_z.o -g ../misc/xcc_z.cpp
	
../o_files/client.o: client.cpp
	g++ -DNDEBUG -I ../misc -I . -O3 -c -o ../o_files/client.o -g client.cpp
	
../o_files/config.o: config.cpp
	g++ -DNDEBUG -I ../misc -I . -O3 -c -o ../o_files/config.o -g config.cpp

../o_files/connection.o: connection.cpp
	g++ -DNDEBUG -I ../misc -I . -O3 -c -o ../o_files/connection.o -g connection.cpp
	
../o_files/epoll.o: epoll.cpp
	g++ -DNDEBUG -I ../misc -I . -O3 -c -o ../o_files/epoll.o -g epoll.cpp

../o_files/server.o: server.cpp
	g++ -DNDEBUG -I ../misc -I . -O3 -c -o ../o_files/server.o -g server.cpp
	
../o_files/tcp_listen_socket.o: tcp_listen_socket.cpp
	g++ -DNDEBUG -I ../misc -I . -O3 -c -o ../o_files/tcp_listen_socket.o -g tcp_listen_socket.cpp
	
../o_files/tracker_input.o: tracker_input.cpp
	g++ -DNDEBUG -I ../misc -I . -O3 -c -o ../o_files/tracker_input.o -g tracker_input.cpp
	
../o_files/transaction.o: transaction.cpp
	g++ -DNDEBUG -I ../misc -I . -O3 -c -o ../o_files/transaction.o -g transaction.cpp
	
../o_files/udp_listen_socket.o: udp_listen_socket.cpp
	g++ -DNDEBUG -I ../misc -I . -O3 -c -o ../o_files/udp_listen_socket.o -g udp_listen_socket.cpp
	
../o_files/XBT\ Tracker.o: XBT\ Tracker.cpp
	g++ -DNDEBUG -I ../misc -I . -O3 -c -o "../o_files/XBT Tracker.o" -g "XBT Tracker.cpp"

.PHONY:
clean:
	rm -rf xbt_tracker ../o_files/*