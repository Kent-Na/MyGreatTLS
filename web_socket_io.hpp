

//Section 5.2
enum class Frame_type : uint8_t{
    continuation = 0x00,
    text         = 0x01,
    binary       = 0x02,
    close        = 0x08,
    ping         = 0x09,
    pong         = 0x0a,
}

enum class State : uint8_t{
    reading_http_start_line,
    reading_http_request_header,
    accept_reading_http_header,

    upgraded_to_ws = 0x10,
    
    //Reading first 2 bytes of frame header.
    reading_ws_frame_header_0,
    //Reading extended payload length(2 or 8 bytes).
    reading_ws_frame_header_1,
    //Reading masking key(2 bytes).
    reading_ws_frame_header_2,
    
    reading_ws_frame_payload,
};

struct Frame_header{
    //A first byte
    int FIN    :1;
    int RSV1   :1;
    int RSV2   :1;
    int RSV3   :1;
    int opcode :4;

    bool MASK;
    uint8_t masking_key[4];
    uint64_t payload_length;
}


class Web_socket_layer:public io_layer{
    Frame_header read_frame_header;
    uint64_t consumed_payload_length;

    State state;
    uint8_t sec_web_socket_key[24];
    bool is_client;
public:
    size_t read(void* output_buffer, size_t buffer_size);
};

/////////////////
//impl

size_t Web_socket_layer::read(void* output_buffer, size_t buffer_size){
    if (state == reading_data_frame){
        //Consume data buffer first.
        //Direct read
    }
    
    
}
size_t Web_socket_layer::write(void* output_buffer, size_t buffer_size){
    if (state == reading_data_frame){
        //Consume data buffer first.
        //Direct read
    }
}

void Web_socket_layer::low_level_read_ready(){

}

void Web_socket_layer::low_level_write_ready(){

}

//todo: move this function to util.h
//return NULL if begining of target string match with argument.
//or pointer of just next to the end of matched string.
char*  match_str(const char* str, char* begin, char* end){
    char* ptr_test = (char*)str;
    char* ptr_target = begin;
    while (*ptr_test != '\0' && ptr_target != end){
        if (*ptr_test != *ptr_target) return NULL;
        ptr_test   ++;
        ptr_target ++;
    }

    //ptr_test leach the end of string
    if (*ptr_test == '\0')
        return ptr_target;
    //or not
    return NULL;
}


void test_match_str(){
    {
        const char* a = "abc";
        char* b = (char*)"abcdefg";
        char* r = match_str(a, b, b+strlen(b));
        if (r != b + strlen(a)) printf("error on test case 1\n");
    }

    {
        const char* a = "abc";
        char* b = (char*)"a";
        char* r = match_str(a, b, b+strlen(b));
        if (r != NULL) printf("error on test case 2\n");
    }

    {
        const char* a = "abc";
        char* b = (char*)"abc";
        char* r = match_str(a, b, b+strlen(b));
        if (r != b + strlen(a)) printf("error on test case 3\n");
    }

    {
        const char* a = "abc";
        char* b = (char*)"accd";
        char* r = match_str(a, b, b+strlen(b));
        if (r != NULL) printf("error on test case 4\n");
    }
    
    printf("all done\n");
}

//Section 1.3 & Section 4.1
//Return false on error.
bool  Web_socket_laper::read_http_start_line(
                const char* begin, const char* end){
    //GET [path] HTTP/1.1
    //Method must be "GET"
    const char method[] = "GET";
    //space
    const char SP[] = " ";
    //HTTP version must be at least 1.1, and this lib only support 1.1.
    const char http_version[] = "HTTP/1.1";
    
    const char* ptr = begin;

    if (! (ptr = match_str(method, ptr, end))       return false;
    if (! (ptr = match_str(SP, ptr, end))           return false;
    
    //Skip request URI(and last SP)
    for (NULL; ptr<end && ptr != ' '; ptr++) NULL;
    if (ptr == end)
        return false;

    if (! (ptr = match_str(http_version, ptr, end)) return false;
    
    //"ptr" munt leach end of line.
    if (ptr != end)
        return false;

    return true
}

char* skip_http_lws(const char* begin, const char* end){
    //From RFC 2616 Section 2.2
    //LWS = [CRLF] 1*( SP | HT )
    
    char* ptr = begin;
    bool start_with_CRLF = false;
    if (ptr-end > 2 && ptr[0] == 13/*CR*/ && ptr[1] == 10/*LF*/){
        ptr += 2;
        start_with_CRLF = true;
    }
    while (ptr != end && (*ptr == 32/*SP*/ || *ptr == 9/*HT*/)) ptr ++;
    
    //CRLF must be forrowed by a SP or a HT.
    if (start_with_CRLF && ptr < begin+3) return begin;

    return ptr;
}

char* skip_many_http_lws(const char* begin, const char* end){
    char* last = begin;
    char* ptr  = begin;
    do{
        last = ptr;
        ptr = skip_http_lws(ptr, end);
    } while(ptr != last);
    return ptr;
}

void Web_socket_layer::read_http_field_line(
                const char* begin, const char* end){
    //Need the value of Sec-WebSocket-Key field.
    const char* ptr;
    //todo: make it case insensitive
    if (ptr = match_str("Sec-WebSocket-Key:", begin, end)){
        if (end - )
    }
}

//return true when it need to retry
bool Web_socket_layer::read_http_request_line(){
    //read
    //extruct line
    
    //todo: setup begin and end
    const char* begin;
    const char* end;
    const char* ptr = begin+1;

    //Find a CRLF not forrowed by a SP or a HT.
    for (NULL; ptr<end; ptr++){
        if ( not (ptr[-1] == 13/*CR*/ && ptr[0] == 10/*LF*/))
            continue;
        if (ptr == begin+1){
            //end of http header
            //todo: write this 
            return;
        }

        if (ptr+1 == end) return;
        if (not (ptr[1] == 32/*SP*/ || ptr[1] == 9/*HT*/))
            break;
    }
    
    //Doesn't leach end of line
    if (ptr == end) return;

    if (state == State::reading_http_start_line){
        read_http_start_line(begin, ptr-1);
    }
    else if (state == State::reading_http_request_header){
        read_http_field(begin, ptr-1);
    }
}

//Section 1.3
void Web_socket_layer::send_http_response_header(){
    const char ws_header[] = 
        "HTTP/1.1 101 Switching Protocols\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        "Sec-WebSocket-Acccept: "/*Generated Accpet key here*/;

    const char CR_NL[] = "\r\n";

    uint8_t buffer[24+36];
    //Section 4.2.2
    uint8_t str[36] = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    memcpy(buffer, sec_web_socket_key, 24);
    memcpy(buffer+24, str, 36);

    uint8_t hash[20];
    SHA1(buffer, 24+36, hash);

    uint8_t base64[28];
    base64(hash, 20, base64);

    force_write(ws_header, sizeof ws_header-1);
    force_write(base_64, 28);
    force_write(CR_NL, sizeof CR_NL-1);
    force_write(CR_NL, sizeof CR_NL-1);

    state = upgraded
}

