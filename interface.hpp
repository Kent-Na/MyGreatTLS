//////////////////
//
//This is ssl/websocket io stack libraly for non-blocking io.
//
//The goal of this project is provide the single solid interface for
//the unix file discription(socket, file), TLS1.2 and WebSocket.
//Which should work with epoll/kqueue event system and adaptable 
//to Boost.asio.
//
//
//Web socket layer support RFC 6455.

//namespace tuna_cat{

class Io_layer;
class Io_stack_delegate;

template<typename Delegate_type = Io_stack_delegate>
class Io_stack{
    Io_layer* top;

public:
    Io_stack();

    void push(Io_layer* layer);

    size_t read(void* out_buffer, size_t size);
    size_t write(void* out_buffer, size_t size);
   
    //Connect as a client.
    void connect();
    //Accept a client connection as a server.
    void accept();
	
	//for better record fragmentation.
	void flash();
    //disconnect
    void close();

    bool is_connected();

    void set_delegate(Delegate_type* delegate);
};

class Io_stack_delegate{
public:
    //callbacks
    virtual void read_ready(Io_stack<>* stack){}
    virtual void write_ready(Io_stack<>* stack){}
    virtual void on_error(Io_stack<>* stack){}
    virtual void on_close(Io_stack<>* stack){}
};

class Io_layer{
protected:
    Io_layer* low_level_io;
    Io_layer* high_level_io;
public:
    Io_layer();
    virtual ~Io_layer();
    
    void push(Io_layer* layer);

    //Connect as a client.
    //virtual void connect();
    //Accept a client connection as a server.
    //virtual void accept();
	
	//todo: Put better name.
	virtual bool is_connected();


//basic io.
//Read and write method may block when the lowest level io read/write
//operation are blocking. Read method may be blocked by the lowest level
//bloking write and vice versa.

    //virtual size_t read(
        //void* output_buffer, size_t buffer_size,
        //uint32_t* flags
    //);
    //virtual bool write(
        //void* input_buffer, size_t buffer_size, uint32_t flags
    //);

    virtual size_t read(
            void* output_buffer,
            size_t buffer_size);
    virtual size_t write(
            void* output_buffer,
            size_t buffer_size);

////////////////
//Event chain (Called from low level io.)
    //These method will called when at least a byte of data are available.
    virtual void low_level_read_ready();
    virtual void low_level_write_ready();

    virtual void low_level_on_close();
    virtual void low_level_on_error();
};

template<typename Delegate_type>
class Dummy_layer: public Io_layer{
    Delegate_type* delegate;
    Io_stack<Delegate_type>* stack;
    void low_level_read_ready(){
        if (delegate) delegate->read_ready(stack);
    }
    void low_level_write_ready(){
        if (delegate) delegate->write_ready(stack);
    }

    void low_level_on_close(){
        if (delegate) delegate->on_close(stack);
    }
    void low_level_on_error(){
        if (delegate) delegate->on_error(stack);
    }
    size_t read(
            void* output_buffer,
            size_t buffer_size){
        if (low_level_io)
            return low_level_io->read(output_buffer, buffer_size);
        else
            return 0;
    }
    size_t write(
            void* output_buffer,
            size_t buffer_size){
        if (low_level_io)
            return low_level_io->write(output_buffer, buffer_size);
        else
            return 0;
    }
    public:
    Dummy_layer(Io_stack<Delegate_type>* stack){
        this->stack = stack;
        this->delegate = nullptr;
    }
    Dummy_layer(Io_stack<Delegate_type>* stack, Delegate_type* delegate){
        this->stack = stack;
        this->delegate = delegate;
    }
};

template<typename Delegate_type>
Io_stack<Delegate_type>::Io_stack(){
    top = nullptr;
}

template<typename Delegate_type>
void Io_stack<Delegate_type>::push(Io_layer* layer){
    if (top){
        top->push(layer);
    }
    top = layer;
}

template<typename Delegate_type>
size_t Io_stack<Delegate_type>::read(void* buffer, size_t size){
    if (top){
        return top->read(buffer, size);
    }
    else{
        return 0;
    }
}

template<typename Delegate_type>
void Io_stack<Delegate_type>::set_delegate(Delegate_type* delegate){
    push(new Dummy_layer<Delegate_type>(this, delegate));
}

Io_layer::Io_layer(){
    high_level_io = NULL;
    low_level_io = NULL;
}
Io_layer::~Io_layer(){
    high_level_io = NULL;
    low_level_io = NULL;
}
void Io_layer::push(Io_layer* layer){
    if (this->high_level_io || layer->low_level_io){
        printf("error\n");
        return;
    }
    this -> high_level_io = layer;
    layer-> low_level_io  = this;
}
size_t Io_layer::read(
        void* output_buffer,
        size_t buffer_size){
    return 0;
}
size_t Io_layer::write(
        void* output_buffer,
        size_t buffer_size){
    return 0;
}
bool Io_layer::is_connected(){
	return false;
}
void Io_layer::low_level_read_ready(){

}
void Io_layer::low_level_write_ready(){

}

void Io_layer::low_level_on_close(){

}
void Io_layer::low_level_on_error(){

}
/*
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

*/
//}//namespace tuna_cat
