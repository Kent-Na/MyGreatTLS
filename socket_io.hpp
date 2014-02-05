#include <sys/socket.h>

class Socket_layer: public Io_layer{
    int fd;

public:
    Socket_layer();

    void connect(int fd);
	bool is_connected();

    size_t read(void* output_buffer, size_t buffer_size);
    size_t write(void* output_buffer, size_t buffer_size);

    void low_level_read_ready();
    void low_level_write_ready();

    void low_level_on_error();
    void low_level_on_closed();
    
    void epoll_event_handler(struct epoll_event* ev);
};

Socket_layer::Socket_layer(){
    fd = -1;
}

void Socket_layer::epoll_event_handler(struct epoll_event* ev){
    if (high_level_io){
        if (ev->events & EPOLLIN){
            high_level_io->low_level_read_ready();
        }
        if (ev->events & EPOLLOUT){
            high_level_io->low_level_write_ready();
        }
    }
}

void Socket_layer::connect(int fd){
    this->fd = fd;
}

bool Socket_layer::is_connected(){
	return (fd != -1);
}

size_t Socket_layer::read(void* output_buffer, size_t buffer_size){
#ifdef MSG_NOSIGNAL
    ssize_t r_val = recv(fd, output_buffer, buffer_size, MSG_NOSIGNAL);
#else
    ssize_t r_val = read(fd, output_buffer, buffer_size);
#endif

    if (r_val == 0){
        high_level_io->low_level_on_close();
        return 0;
    }
    if (r_val == -1){
        high_level_io->low_level_on_error();
        return 0;
    }
    return r_val;
}
size_t Socket_layer::write(void* output_buffer, size_t buffer_size){
#ifdef MSG_NOSIGNAL
    ssize_t r_val = send (fd, output_buffer, buffer_size, MSG_NOSIGNAL);
#else
    ssize_t r_val = write(fd, output_buffer, buffer_size);
#endif

    if (r_val == 0){
        high_level_io->low_level_on_close();
        return 0;
    }
    if (r_val == -1){
        high_level_io->low_level_on_error();
        return 0;
    }
    return r_val;
}

//Ignore all low level events
void Socket_layer::low_level_read_ready(){
    return;
}
void Socket_layer::low_level_write_ready(){
    return;
}
void Socket_layer::low_level_on_error(){
    return;
}
void Socket_layer::low_level_on_closed(){
    return;
}
