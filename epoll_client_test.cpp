#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/epoll.h>

#include <functional>

uint16_t hton16(uint16_t val){
    return htons(val);
}
uint16_t ntoh16(uint16_t val){
	return hton16(val);
}
uint32_t hton32(uint32_t val){
    return htonl(val);
}
uint64_t hton64(uint64_t val){
	uint32_t *tmp_in = (uint32_t*)&val;
	uint32_t tmp_out[2] = {
		hton32(tmp_in[1]),
		hton32(tmp_in[0]),
	};
    return *(uint64_t*)tmp_out;
}

extern "C"{
#include "../rcp_buffer/rcp_buffer.h"
}
#include "../rcp_buffer/rcp_buffer_cpp.h"
#include "../rcp_buffer/rcp_buffer_reader.h"
#include "interface.hpp"
#include "socket_io.hpp"
#include "ssl_io.cpp"

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#include <sys/socket.h>
#undef _GNU_SOURCE
#else
#include <sys/socket.h>
#endif



struct Epoll_event_handle{
    std::function<void(struct epoll_event*)> on_event;
};

class Client:public Io_stack_delegate{
    Io_stack<>* io_stack; 
public:
    Client(){
        //buffer.init(4096);
    }
    void read_ready(Io_stack<>* stack){
        printf("read_ready\n");
        uint8_t buffer[1024];
        size_t r_val = stack->read((void*)buffer, 1024);
        //printf("%i, %s\n", r_val, buffer);
        //auto s = io_stack->read(buffer.space(), buffer.space_size());
        //buffer.supplied(s);
    }
    void write_ready(Io_stack<>* stack){
        printf("read_ready\n");
        //auto s = io_stack->write(buffer.data(), buffer.data_size());
        //buffer.consumed(s);
        //buffer.cleanup();
    }
};

int main(int argc, char** argv){
    
    constexpr uint16_t port = 3000;
    
    //////////
    //epoll
    int epoll_fd = epoll_create(10);
    
    ///////////////
    //connect
    {
		const char* ip = "127.0.0.1";
        int r_val;
        struct sockaddr_in sockadd;
        bzero(&sockadd, sizeof sockadd);
        sockadd.sin_family = AF_INET;
        sockadd.sin_addr.s_addr = inet_addr(ip);
        sockadd.sin_port = hton16(port);
        
        int fd = socket(AF_INET, SOCK_STREAM|SOCK_NONBLOCK, 0);
        int val = 1;
        r_val = connect(fd, (struct sockaddr*)&sockadd, sizeof sockadd);

		Io_stack<>* stack = new Io_stack<>;
		Socket_layer* s_layer = new Socket_layer;
		Ssl_layer* ssl_layer = new Ssl_layer;
		Client* client = new Client;
		stack->push(s_layer);
		stack->push(ssl_layer);
		s_layer->connect(fd);
		ssl_layer->connect();
		stack->set_delegate(client);
		
		Epoll_event_handle *ev_h = new Epoll_event_handle;

		ev_h->on_event = [fd, s_layer](
				struct epoll_event* ev) -> void{
			printf("on_event\n");
			s_layer->epoll_event_handler(ev);
		};

		struct epoll_event ev;
		ev.events = EPOLLIN|EPOLLOUT|EPOLLPRI|EPOLLRDHUP|EPOLLET;
		ev.data.ptr = (void*)ev_h;
		r_val = epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &ev);
    }


    //////////////
    // main event loop
    

    constexpr int max_event_count = 16;
    struct epoll_event events[max_event_count];
    while (1){
        int r_val = epoll_wait(epoll_fd, events, max_event_count, -1);
        if (r_val == -1){
            if (errno == EINTR){
                continue;
            }
            else{
                return 0;
            }
        }
        for (int i = 0; i<r_val; i++){
            Epoll_event_handle* ev_h = 
                    (Epoll_event_handle*) events[i].data.ptr;
            ev_h->on_event(events+i);
        }
    }
}
