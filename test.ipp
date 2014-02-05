


int main(int argc, char** argv){
    //////////
    //Sample of good old way (blocking-io).
    
    const char* ip = "127.0.0.1";
    const int port = 4000;

    auto* ssl = tuna_cat::socket_connect(ip, port);
    const char* send_str = "Hellow World!!"
    ssl->write(send_str, strlen(send_str)+1);
    
    uint8_t* buffer[4096];
    ssl->read(buffer, 4096);
    ssl->close();

    return 0;
}
