CXX = g++

SERVER = tcp_server
CLIENT = tcp_client

all: $(SERVER) $(CLIENT)

$(SERVER): tcp_server.cpp
	$(CXX) tcp_server.cpp -o $@

$(CLIENT): tcp_client.cpp
	$(CXX) tcp_client.cpp -o $@

clean:
	rm -f $(SERVER) $(CLIENT)