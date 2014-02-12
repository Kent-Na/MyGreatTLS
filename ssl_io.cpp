#include "ssl_io.h"

namespace ssl{

Record_io_layer::Record_io_layer(){
	work_buffer.init(initial_buffer_size);
	
	state == State::read_header;
}
Record_io_layer::~Record_io_layer(){
	work_buffer.deinit();
}

void Record_io_layer::internal_error(const char* err_message){
	printf("internal_err: %s\n", err_message);
}

void Record_io_layer::alert(Alert_messages, bool fatal){

}

bool load_to_buffer(
		std::function<size_t(void*,size_t)> read_function, 
		rcp::buffer<>* buffer,
		size_t size){
    size_t data_size = buffer->data_size();
    if (size <= data_size) return true;
    size_t required_size = size - data_size;
    size_t space_size = buffer->space_size();
    if (required_size > space_size){
        //todo: expand buffer
        printf("Not enough buffer(request = %i)\n",(int) size);
        return false;
    }
    
    //Total data size read from.
    size_t read_size = 0;

    while(required_size){
        size_t result = 
			read_function(buffer->space(), required_size);
        if (result == 0) return false;
        required_size -= result;
        read_size += result;
		buffer->supplied(result);
    }

    return true;
}

void Record_io_layer::set_state(State new_state){
	this->state = new_state;
}
///////
//Read data until buffer has specified data size
bool Record_io_layer::load(size_t s){
	auto f = [&](void* b, size_t s)->size_t{
		return low_level_io->read(b,s);
	};
	return load_to_buffer(f, &work_buffer, s);
}

size_t Record_io_layer::read_record(Content_type type, void* d, size_t s){
	printf("read_rec\n");
	size_t total_result = 0;

	while(1){
		if (state == State::read_header){
			bool compleate = read_record_header();
			if (not compleate) return total_result;
		}
		if (state == State::read_fragment){
			if (record_header.content_type != type) return 0;
			size_t result = 
				read_record_fragment(
						(void*)((uint8_t*)d+total_result), s-total_result);
			if (result==0) return total_result;
			total_result+=result;
		}
	}
	//internal_error("state corrupted");
	//return 0;	
}

bool Record_io_layer::read_record_header(){
	printf("read rec head\n");
    if (state != State::read_header)
        internal_error("state corrupted");
    bool compleate_load = load(5);
    if (not compleate_load) return false;
	
	uint8_t *raw_bytes = work_buffer.data();
	record_header.content_type = (Content_type)raw_bytes[0];
	record_header.major_version = raw_bytes[1];
	record_header.minor_version = raw_bytes[2];
	record_header.length = (raw_bytes[3]<<8)+raw_bytes[4];

	work_buffer.consumed(5);
	work_buffer.cleanup();
	remain_fragment_size = record_header.length;
	set_state(State::read_fragment);
	printf("header received (t = %i)\n", (int)record_header.content_type);
	return true;
}

size_t Record_io_layer::read_record_fragment(void* d, size_t s){
	size_t supply_size = s;
	if (remain_fragment_size <= supply_size)
		supply_size = remain_fragment_size;
	size_t result = low_level_io->read(d, supply_size);
	remain_fragment_size -= supply_size;
	if (remain_fragment_size == 0)
		set_state(State::read_header);
	return result;
}

size_t Record_io_layer::write_record(Content_type type, void* d, size_t s){
    if (s >= 1<<16){
        internal_error("exceed record size remit");
        return 0;
    }
    uint8_t header[5];
    header[0] = (uint8_t)type;		//content type
    header[1] = 3;          //major version
    header[2] = 3;			//minor version
    header[3] = (s & 0xFF00)>>8;
    header[4] = s & 0xFF;
    
    size_t result;
    result = low_level_io->write(header, 5);
    if (result != 5)
        internal_error("ssl_write_error");

	//todo: Compless and encrypt here
    result = low_level_io->write(d, s);
    if (result != s)
        internal_error("ssl_write_error");
    
	return s;
}

/////////////////////////////////
//Record event
////////////////////////

void Record_event_layer::proceed(){
    if (Record_io_layer::state == Record_io_layer::State::read_header){
        bool compleate = Record_io_layer::read_record_header();
        if (not compleate) return;
    }
    if (Record_io_layer::state == Record_io_layer::State::read_fragment){
        if (Record_io_layer::record_header.content_type == 
                                    Content_type::handshake){
            Handshake_layer::read_ready();
        }
    }
}

void Record_event_layer::low_level_read_ready(){
	proceed();
}
void Record_event_layer::low_level_write_ready(){
	proceed();
}

void Record_event_layer::connect(){
	if (not low_level_io)
		internal_error("missing low_level_io");
	if (not low_level_io->is_connected())
		internal_error("low_level_io must be connected first");
	Handshake_layer::start_client_handshake();
}

bool Record_event_layer::is_connected(){
	//todo: rewrite this to proper implement.
	return low_level_io->is_connected();
}



//////////////////////////////////
//Handshake
//////////////////

Handshake_layer::Handshake_layer(){
	work_buffer.init(initial_buffer_size);
}
Handshake_layer::~Handshake_layer(){
	work_buffer.deinit();
}

void Handshake_layer::set_state(State state, Sub_state sub_state){
	this->state = state;
	this->sub_state = sub_state;
	printf("hs_s:%i %i\n", (int)state, (int)sub_state);
}

void Handshake_layer::proceed(){
	while (1){
		if (state == State::read_header){
			if (not read_handshake_header())
				break;
		}
		if (state == State::read_body){
			if (not load_handshake_body())
				break;
		}
		if (state == State::process){
			if (sub_state == Sub_state::write_client_hello){
				write_client_hello();
			}
			else if (sub_state == Sub_state::read_server_hello){
				process_server_hello();
			}
			else if (sub_state == Sub_state::read_certificate){
				process_certificate();
			}
			else if (sub_state == Sub_state::read_server_hello_done){
				process_server_hello_done();
			}
		}
	}
}
void Handshake_layer::read_ready(){
	proceed();
}
void Handshake_layer::write_ready(){
	proceed();
}

size_t Handshake_layer::write_content(void* d, size_t s){
    return write_record(Content_type::handshake, d, s);
}

//Load decompless and decrypted handshake record body to "work_buffer".
//Return true when the work_buffer has more than data specified 
//in 1st argument.
bool Handshake_layer::load(size_t s){
	printf("handshake load\n");
	auto f = [&](void* b, size_t s) -> size_t {
		return read_record(Content_type::handshake, b, s);
	};
	return load_to_buffer(f, &work_buffer, s);
}

bool Handshake_layer::read_handshake_header(){
    if (state != State::read_header)
        internal_error("State corrupted");
    if (not load(4)) return false;

    uint8_t *in = work_buffer.consumed(4);
    header.msg_type = (Handshake_type)in[0];
    header.length = in[1]<<16|in[2]<<8|in[3];
	printf("handshake_header[%i]\n",(int)header.msg_type);
	set_state(State::read_body, sub_state);
    return true;
}

bool Handshake_layer::load_handshake_body(){
    if (state != State::read_body)
        internal_error("State corrupted");
    if (not load(header.length)) return false;
	set_state(State::process, sub_state);
    return true;
}


void Handshake_layer::start_server_handshake(){
    //todo: test pre condition
	set_state(State::process, Sub_state::read_client_hello);
	proceed();
}

void Handshake_layer::start_client_handshake(){
	set_state(State::process, Sub_state::write_client_hello);
	proceed();
}

bool Handshake_layer::write_client_hello(){
	printf("w client hello\n");
    constexpr uint8_t session_id_length = 0;
    constexpr uint8_t cipher_suites_count = 1;
    constexpr uint8_t complession_method_count = 1;
    constexpr uint8_t LEN= 
        2+32+
        1+session_id_length+
        2+cipher_suites_count*2+
        1+complession_method_count;

    
    uint8_t client_hello_template[] = {
        (uint8_t)Handshake_type::client_hello, //msg_type
        0x00, 0x00, LEN,             //length
        0x03, 0x03,                   //client_version(TLS1.2)

        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
        //gmt_unix_time+random_bytes

        0x00,                         //session_id(length=0)
        0x00, 0x02,                   //cipher_suites_length
        0x00, 0x3D,                   //cipher_suites
        //0x00, 0x6B,                   //cipher_suites
                                      //TLS_DHE_RSA_WITH_AES_256_CBC_SHA256
        0x01, 0x00,                   //compression_method(length=0)
    };

    uint8_t *random_bytes = client_hello_template+6;
    //memo:This is a terrible idea to using constant random value in there.
    //todo:use real random
    uint8_t bad_random[32] = {
        0xdf, 0xd9, 0x44, 0xd0,  0x4c, 0xd9, 0x13, 0x49, 
        0x97, 0x11, 0x36, 0x7a,  0xf6, 0x9b, 0x66, 0x02,
        0x06, 0x59, 0x6c, 0x21,  0x8f, 0x0e, 0xaf, 0x32, 
        0xea, 0x5b, 0x0b, 0xf5,  0xd1, 0x11, 0x52, 0x95, 
    };
	memcpy(random_bytes, bad_random, 32);
    //overwrite UNIX time
    uint32_t base_time = hton32(time(NULL));
    *(uint32_t*)random_bytes = base_time;

    size_t result = 
		write_content(client_hello_template, sizeof client_hello_template);
	if (result != 0){
		set_state(State::read_header, Sub_state::read_server_hello);
		return true;
	}
	else{
		return false;
	}
}

void Handshake_layer::process_server_hello(){
    printf("server hello processing\n");
    if (state != State::process)
        internal_error("State corrubted");
	if (header.msg_type != Handshake_type::server_hello)
		internal_error("unexpected handshake type.");

	rcp::buffer_reader<uint8_t> reader(&work_buffer);

	//Protocol version
    uint8_t major_version = reader.take<uint8_t>(0);
    uint8_t minor_version = reader.take<uint8_t>(0);
	
	//Random
	for (int i= 0; i<32; i++)
		reader.skip<uint8_t>();

    //Session_id
	uint8_t session_id_length = reader.take<uint8_t>(0);
	for (int i= 0; i<session_id_length; i++)
		reader.skip<uint8_t>();

    //cipher_suite and complession method
	uint16_t cipher_suite = ntoh16(reader.take<uint16_t>(0));
	uint8_t compression_method = reader.take<uint8_t>(0);

	//memo: extension here(need to read and send alert if required.)

	if (reader.is_failed()){
        alert(Alert_messages::unexpected_message, true);
        return;
	}

    if (not (major_version == 3 && minor_version == 3)){
        alert(Alert_messages::protocol_version, true);
        return;
    }

    printf("server hello received\n");
	work_buffer.consumed_all();
	work_buffer.cleanup();
	set_state(State::read_header, Sub_state::read_certificate);
}

void Handshake_layer::process_certificate(){
    printf("server hello processing\n");
    if (state != State::process)
        internal_error("State corrubted");
	if (header.msg_type != Handshake_type::certificate)
		internal_error("unexpected handshake type.");

	rcp::buffer_reader<uint8_t> reader(&work_buffer);

	//Protocol version
    uint32_t total_length = reader.take_24nash(0);
	uint32_t remain = total_length;

	while (remain != 0){
		uint32_t length = reader.take_24nash(0);
		if (length == 0){
			alert(Alert_messages::unexpected_message, true);
			return;
		}
		void* certificate = reader.take_byte_pointer<void>(length);
		remain -= length + 3;
		printf("c\n");
		//if (certificate)
		//	printf("c = \n%s\n", certificate);
	}
	
	//memo: extension here(need to read and send alert if required.)

	if (reader.is_failed()){
        alert(Alert_messages::unexpected_message, true);
        return;
	}
	
	if (work_buffer.data_size() != 0){
        alert(Alert_messages::unexpected_message, true);
        return;
	}

    printf("cirtificate received\n");
	work_buffer.consumed_all();
	work_buffer.cleanup();
	set_state(State::read_header, Sub_state::read_server_hello_done);
}

void Handshake_layer::process_server_hello_done(){
    printf("server hello done processing\n");
    if (state != State::process)
        internal_error("State corrubted");
	if (header.msg_type != Handshake_type::server_done)
		internal_error("unexpected handshake type.");

	if (work_buffer.data_size() != 0){
        alert(Alert_messages::unexpected_message, true);
        return;
	}

    printf("server hello done\n");
	work_buffer.cleanup();
	set_state(State::process, Sub_state::write_client_key_exchange);
}

}//namespace ssl
