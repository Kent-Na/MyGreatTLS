

void Core_io_layer::trigger_read(){
    next_io->try_base_read();
}

void Core_io_layer::trigger_write(){
    next_io->try_base_read();
}
