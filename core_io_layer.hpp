

class Core_io_layer:public Io_layer{
    Core_io* core_io;
private:

    void trigger_read();
    void trigger_write();
}
