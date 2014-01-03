//////////////////
//
//This is ssl/websocket io stack libraly for non-blocking io.
//
//Only the SSL Protocol Version 3.0 descrived in RFC 6101 was supported.
//Web socket version is RFC 6455.



namespace tuna_cat{

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

    void connect();
    void accept();

//basic io.
    size_t read(
            void* output_buffer,
            size_t buffer_size);
    size_t write(
            void* output_buffer,
            size_t buffer_size);

////////////////
//Event chain (Called from base io.)
    void try_base_read();
    void try_base_write();

    void base_io_error();
    void base_io_closed();
};

class core_io{
public:
    ssize_t read(void* out, size_t size);
    ssize_t write(void* out, size_t size);

};

class Core_io_layer:public io_layer{

    void trigger_read();
    void trigger_write();
};

class ssl_layer:public io_layer{

};

class web_socket_layer:public io_layer{

};

class application_layer:public io_layer{
    //User code will be here.
};

}//namespace tuna_cat
