#include "ssl_io.h"

namespace ssl{

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
    if (size >= data_size) return true;
    size_t required_size = size - data_size;
    size_t space_size = buffer->space_size();
    if (required_size < space_size){
        //todo: expand buffer
        printf("Not enough buffer\n");
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
    }

    return true;
}

///////
//Read data until buffer has specified data size
bool Record_io_layer::load(size_t s){
	auto f = [&](void* b, size_t s)->size_t{
		return low_level_io->read(b,s);
	};
	return load_to_buffer(f, &work_buffer, s);
}

/////
//Read, decompless, decrypt and put data into wark_buffer until specified
//data size.
/*
bool Record_io_layer::load_decoded(rcp_buffer* buffer, size_t size){
    size_t data_size = rcp_buffer_data_size(buffer);
    if (data_size >= size) return true;
    
    size_t request_size = size - data_size;
    size_t space_size = rcp_buffer_space_size(buffer);
    if (space_size > request_size){
        //todo: abort or expand buffer
    }

    size_t r_val = low_level_io->read(
        rcp_buffer_space(buffer),
        size-data_size
        )

    data_size = rcp_buffer_data_size(buffer);
    if (data_size >= size) return true;
    else return false;
}
*/

size_t Record_io_layer::read_record(Content_type type, void* d, size_t s){
	if (state == State::read_header){
		bool compleate = read_record_header();
		if (not compleate) return 0;
	}
	if (state == State::read_fragment){
		if (record_header.content_type != type) return 0;
		//memo: decode and decrypto
		size_t consume_size = s;
		size_t data_size = work_buffer.data_size();
		if (consume_size < data_size){
			work_buffer.consume(d, s);
			return s;
		}
		else{
			work_buffer.consume(d, data_size);
			work_buffer.cleanup();
			return data_size;
		}
	}
	internal_error("state corrupted");
	return 0;	
}

bool Record_io_layer::read_record_header(){
    if (state != State::read_header)
        internal_error("state corrupted");
    bool compleate_load = load(5);
    if (not compleate_load) return false;
	
	uint8_t raw_bytes[5];
	record_header.content_type = (Content_type)raw_bytes[0];
	record_header.major_version = raw_bytes[1];
	record_header.minor_version = raw_bytes[2];
	record_header.length = (raw_bytes[3]<<8)+raw_bytes[4];

	work_buffer.consumed(5);
	work_buffer.cleanup();
	printf("header received\n");
	return true;
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
/*
void Ssl_layer::read_and_process_record_fragment(){
    if (read_header.content_type == change_cipher_spec){

    }
    else if (read_header.content_type == alert){

    }
    else if (read_header.content_type == handshake){

    }
    else if (read_header.content_type == application_data){
        //Application data are proccessed in "read" method.
    }
    else{
        //Bad content type.
        //memo: There is no description abuot how to handle bad 
        //content type.
    }
}
*/
/*
void Ssl_layer::read_record_fragment(){
    if (record_state != XXX_reading_fragment)
        err();

    record_state = XXX_processing;
}

void Ssl_layer::process_non_app_data_frame(){

}

void Ssl_layer::connect(){

}
*/

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

//process loaded client hello message
void Handshake_layer::process_client_hello(){
    if (state != State::process)
        internal_error("State corrubted");
    uint8_t* input_begin = work_buffer.data();
    uint8_t* input_ptr = input_begin;
    uint8_t* input_end = 
        input_begin + work_buffer.data_size();
    
    ///////////////////////////////////
    //version and random
    if (input_end < input_ptr + 2/*version*/ + 32/*random*/){
        alert(Alert_messages::unexpected_message, true);
        return;
    }

    uint8_t major_client_version = input_ptr[0];
    uint8_t minor_client_version = input_ptr[1];
    if (not (major_client_version == 3 && minor_client_version == 3)){
        alert(Alert_messages::protocol_version, true);
        return;
    }

    input_ptr += 2;
    //todo: read_random_here
    
    input_ptr += 32;

    ////////////////////////////////////
    //session_id
    if (input_end < input_ptr + 1/*sessino_id_length*/){
        alert(Alert_messages::unexpected_message, true);
        return;
    }
    uint8_t session_id_length = input_ptr[0];
    input_ptr += 1;

    if (input_end < input_ptr + session_id_length){
        alert(Alert_messages::unexpected_message, true);
        return;
    }
    input_ptr += session_id_length;
    //todo: read session_id here 


    ////////////////////////////////////
    //session_id
    if (input_end < input_ptr + 2/*cipher_suite_length*/){
        alert(Alert_messages::unexpected_message, true);
        return;
    }
    uint16_t cipher_suites_length = input_ptr[0]<<8 | input_ptr[1];
    input_ptr += 2;

    if (input_end < input_ptr + cipher_suites_length){
        alert(Alert_messages::unexpected_message, true);
        return;
    }
    //todo: read cipher_suites here 
    input_ptr += cipher_suites_length;

    ////////////////////////////////////
    //compression_method
    if (input_end < input_ptr + 1/*complession_method_length*/){
        alert(Alert_messages::unexpected_message, true);
        return;
    }
    uint8_t complession_method_length = input_ptr[0];
    input_ptr += 1;

    if (input_end < input_ptr + complession_method_length){
        alert(Alert_messages::unexpected_message, true);
        return;
    }
    //todo: read compression_method here 
    input_ptr += complession_method_length;

    //////////////////////////////
    //send server hello here
    
    printf("client hello received\n");
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
        0x00, 0x6B,                   //cipher_suites
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
    //overwrite UNIX time
    uint32_t base_time = hton32(time(NULL));
    *(uint32_t*)random_bytes = base_time;

    size_t result = 
		write_content(client_hello_template, sizeof client_hello_template);
	if (result != 0){
		set_state(State::read_header, Sub_state::read_client_hello);
		return true;
	}
	else{
		return false;
	}
}

}//namespace ssl
