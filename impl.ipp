#include "interface.hpp"



void io_stack::run_read_chain(){
    auto front = stack.front();

    
}

struct buffer{

};

struct request{

};

void io_core_buffer_layer::async_read(size_t size, io_callback callback){

}

void io_core_buffer_layer::core_read_event(
    size_t size, io_callback callback){

    Request req = this->read_request;
    ssize_t result = core->read(buffer, size);

}


void socket_io_layer::on_read(){
    next->on_read();
}

void socket_io_layer::on_write(){
    next->on_write();
}


