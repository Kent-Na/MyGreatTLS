


class io_with_buffer: public io_layer{
    rcp_buffer read_buffer;    
    rcp_buffer write_buffer;    
public:

    void queue_read(void* data, size_t size);
    void queue_write(void* data, size_t size);

};
