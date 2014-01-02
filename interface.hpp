//////////////////
//
//This liblary only support the SSL Protocol Version 3.0 descrived in
//RFC 6101.



namespace tuna_cat{
/////////////////////////
//Design A (wrapper)
///
class io{
public:
    virtual ~io() = 0;
    virtual ssize_t read(void* ptr, size_t length) = 0;
    virtual ssize_t write(void* ptr, size_t length) = 0;

    void close();
};

class wrapper_io:public io{
    io* base_io;
public:
    void connect();
    void accept();
    
    ////
    //Standard io methods
    //Will block if base io is blocking.
    ssize_t read(void* ptr, size_t length);
    ssize_t write(void* ptr, size_t length);

    ////
    //Event driven io methods

    //tell ssl_io
    //It will call back methods.
    void process_raw_read();
    void process_raw_write();

    //callback methods
    void(*on_readable)();
    void(*on_writable)();

    void(*on_read_compleate)(void* ptr, size_t length);
    void(*on_write_compleate)(void* ptr, size_t length);
    
};

class ssl_io:public wrapper_io{

};

class web_socket_io:public wrapper_io{

};

///////////////
//Design B(stack)
//
class io_stack{
    std::vector<io_layer*> stack;
    public:
    size_t read(void* out_buffer, size_t size);    
    size_t write(void* out_buffer, size_t size);    

    void mark_read_data_available();
    void mark_write_data_available();
    
    void close();

    bool is_connected();
};

class io_layer{
    public:
    //request_read_operation
    void 
    async_read(
            void* data,
            size_t size, 
            void(*on_compleate)(void* user_data));

    //request_write_operation
    void 
    async_write(
            void* data,
            size_t size, 
            void(*on_compleate)(void* user_data));
};

class non_blocking_io_core{
public:
    ssize_t read(void* out, size_t size);
    ssize_t write(void* out, size_t size);
};

class non_blocking_io_core:public io_layer{
    buffer read_buffer;
    buffer write_buffer;

    request active_read_request;
    request active_write_request;

};

class ssl_layer:public io_layer{

};

class web_socket_layer:public io_layer{

};

class application_layer:public io_layer{
    //User code will be here.
};

}//namespace tuna_cat
