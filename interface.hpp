//////////////////
//
//This liblary only support the SSL Protocol Version 3.0 descrived in
//RFC 6101.



namespace tuna_cat{

class io{
public:
    virtual ~io() = 0;
    virtual ssize_t read(void* ptr, size_t length) = 0;
    virtual ssize_t write(void* ptr, size_t length) = 0;

    void close();
}

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

}//namespace tuna_cat
