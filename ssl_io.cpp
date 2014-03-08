#include "ssl_io.h"

namespace ssl{

using namespace openssl;

/////////////////////////
//utilities
static void print_hex(uint8_t *data, size_t data_len){
	for (int i = 0; i<data_len; i++){
		printf("%02X ", data[i]);
		if ((i%16) == 15)
			printf("\n");
	}

	printf("\n");
}

struct SHA_HMAC{
	SHA::State sha;
	uint8_t ipad_key[64];
	uint8_t opad_key[64];

	void init(uint8_t *input_key, size_t input_key_len){
		uint8_t* key = input_key;
		size_t key_len = input_key_len;	

		constexpr size_t   key_hash_len = SHA::length;
		uint8_t key_hash[key_hash_len];

		if (key_len > 64){
			SHA::hash(&sha, key, key_len, key_hash);
			key = key_hash;
			key_len = key_hash_len;
		}
		
		for (int i = 0;i<key_len; i++){
			ipad_key[i] = key[i]^0x36;
			opad_key[i] = key[i]^0x5c;
		}
		for (int i = key_len; i<64; i++){
			ipad_key[i] = 0x36;
			opad_key[i] = 0x5c;
		}

		SHA::init(&sha);
		SHA::put(&sha, ipad_key, 64);
	}

	void reinit(){
		SHA::init(&sha);
		SHA::put(&sha, ipad_key, 64);
	}

	void put_data(uint8_t *data, size_t data_len){
		SHA::put(&sha, data, data_len);
	}

	void generate(uint8_t *output){
		SHA::generate(&sha, output);

		SHA::init(&sha);
		SHA::put(&sha, opad_key, 64);
		SHA::put(&sha, output, SHA::length);
		SHA::generate(&sha, output);
	}

	static void generate(
			uint8_t *input_key, size_t input_key_len,
			uint8_t *data, size_t data_len,
			uint8_t *output){
		SHA_HMAC hmac;
		hmac.init(input_key, input_key_len);
		hmac.put_data(data, data_len);
		hmac.generate(output);
	}
};


/////////////
//See RFC 5246  Section 5
//

static void SHA_PRF(
		uint8_t *secret, size_t secret_len, 
		uint8_t *label, size_t label_len, 
		uint8_t *seed, size_t seed_len,
		uint8_t *output, size_t output_len){

	uint8_t A_n[SHA::length];
	uint8_t result[SHA::length];
	for (int i= 0; i<output_len; i+=SHA::length){
		SHA_HMAC hmac;
		hmac.init(secret, secret_len);
		if (i == 0){
			hmac.put_data(label, label_len);
			hmac.put_data(seed, seed_len);
		}
		else{
			hmac.put_data(A_n, SHA::length);
		}
		hmac.generate(A_n);
		
		hmac.reinit();
		hmac.put_data(A_n, SHA::length);
		hmac.put_data(label, label_len);
		hmac.put_data(seed, seed_len);
		hmac.generate(result);
		
		if (output_len-i >= SHA::length)
			memcpy(output+i, result, SHA::length);
		else
			memcpy(output+i, result, output_len-i);
	}
}

//////////////////////////////
//Record_io_layer
//////////

Record_io_layer::Record_io_layer(){
	work_buffer.init(initial_buffer_size);
	
	state == State::read_header;

	const char* input = "test_vector";
	const char* key = "the_key";
	uint8_t out[SHA::length];

	SHA_HMAC hmac;
	hmac.init((uint8_t*)key, strlen(key));
	hmac.put_data((uint8_t*)input, strlen(input));
	hmac.generate(out);

	print_hex(out, SHA::length);
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

size_t Record_io_layer::write_record(
		Content_type type, void* d, size_t s){
	size_t r_val;
	if (write_encrypt)
		r_val = write_record_block_cipher(type, d, s);
	else
		r_val = write_record_plane(type, d, s);
	printf("%zu of %zu written\n", s, r_val);
	return r_val;
}
size_t Record_io_layer::write_record_plane(
		Content_type type, void* d, size_t s){
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

size_t Record_io_layer::write_record_block_cipher(
		Content_type type, void* d, size_t s){
	constexpr size_t iv_size = 16;
	constexpr size_t mac_len = SHA::length;
	//Plus one for length of padding length
	const size_t fragment_base_len = s + mac_len + 1;

	constexpr size_t block_size = 16; //must be 2^n
	
	//data length in last block;
	const size_t last_data_len= (block_size - 1) & fragment_base_len;

	const size_t min_padding_size = 
		(block_size - last_data_len) % block_size;

	// tatal_len must be less than 2^14+2048;
	const size_t total_len  = 
		fragment_base_len + min_padding_size + iv_size;
	
	if (not work_buffer.is_empty()){
		internal_error("work_buffer isn't empty");
		return 0;
	}
	work_buffer.cleanup();

	//todo: test work_buffer.size() here.
	work_buffer.supply(d, s);

	uint8_t mac[mac_len];
	SHA_HMAC hash_state;
	hash_state.init(write_mac_key, 32);

	//this is not good way to do it...
	uint8_t mac_header[13];
	*(uint64_t*)(mac_header+0 ) = hton64(write_sequense_number);
	*( uint8_t*)(mac_header+8 ) = (uint8_t)type;
	*( uint8_t*)(mac_header+9 ) = 3;
	*( uint8_t*)(mac_header+10) = 3;
	*(uint16_t*)(mac_header+11) = hton16(s);

	hash_state.put_data(mac_header, 13);
	hash_state.put_data((uint8_t*)d, s);
	hash_state.generate(mac);

	print_hex(mac, sizeof mac);

	work_buffer.supply(mac, mac_len);
	uint8_t *padding = work_buffer.supplied(min_padding_size+1);
	for (int i= 0; i<min_padding_size+1; i++){
		padding[i] = min_padding_size;
	}

	//print_hex(work_buffer.data(), work_buffer.data_size());

	//encrypt
	uint8_t iv_original[iv_size];
	uint8_t iv[iv_size];
	RNG::generate(NULL, iv_original, iv_size);
	memcpy(iv, iv_original, iv_size);

	//print_hex(iv, iv_size);
	AES_KEY key;
	AES_set_encrypt_key(write_encryption_key, 256, &key);
	//printf("len %02x\n", total_len);
	//printf("len %02x\n", work_buffer.data_size());
	AES_cbc_encrypt(work_buffer.data(), work_buffer.data(),
			work_buffer.data_size(), &key,
			iv, 1);
	//print_hex(iv, iv_size);

	//print_hex(work_buffer.data(), work_buffer.data_size());

	//write_header
    uint8_t header[5];
    header[0] = (uint8_t)type;		//content type
    header[1] = 3;          //major version
    header[2] = 3;			//minor version
    header[3] = (total_len & 0xFF00)>>8;
    header[4] = total_len & 0xFF;
    
    size_t result;
    result = low_level_io->write(header, 5);
    if (result != 5)
        internal_error("ssl_write_error");

    result = low_level_io->write(iv_original, iv_size);
    if (result != iv_size)
        internal_error("ssl_write_error");

	//todo: Compless and encrypt here
    result = 
		low_level_io->write(work_buffer.data(), work_buffer.data_size());
    if (result != work_buffer.data_size())
        internal_error("ssl_write_error");

	//print_hex(header, 5);
	//print_hex(iv, iv_size);
	//print_hex(work_buffer.data(), work_buffer.data_size());

	//AES_set_decrypt_key(write_encryption_key, 256, &key);
	//AES_cbc_encrypt(work_buffer.data(), work_buffer.data(),
			//work_buffer.data_size(), &key,
			//iv, 0);
	//print_hex(iv, iv_size);

	//print_hex(work_buffer.data(), work_buffer.data_size());

	work_buffer.consumed_all();
	work_buffer.cleanup();

	write_sequense_number ++;
    
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
	write_encrypt = 0;
	Handshake_layer::start_client_handshake();
}

bool Record_event_layer::is_connected(){
	//todo: rewrite this to proper implement.
	return low_level_io->is_connected();
}

//////////////////////////////////
//Change_cipher_spec
////////////////////////////

void Change_cipher_spec_layer::read_change_cipher_spec(){
	uint8_t message;
	size_t r_val = read_record(
			Content_type::change_cipher_spec, &message, 1);
	if (r_val == 0) return;

	//todo: implement assert.
	//assert(r_val != 1)

	if (message != 1)return;//send alert here?
	//assert(message != 1);
}
void Change_cipher_spec_layer::write_change_cipher_spec(){
	uint8_t message = 1;
	size_t r_val = write_record(
			Content_type::change_cipher_spec, &message, 1);
	if (r_val == 0) return; //fail
	write_encrypt = 1;
}
void Change_cipher_spec_layer::read_ready(){
	read_change_cipher_spec();
}
void Change_cipher_spec_layer::write_ready(){
	//todo: Retry writing change_cipher_spec here.
	return;
}





//////////////////////////////////
//Handshake
//////////////////

Handshake_layer::Handshake_layer(){
	work_buffer.init(initial_buffer_size);
	//todo: init state and sub_state value.
	server_key = nullptr;
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
			//todo: Solve the problem where unsuccessful write make it 
			//infinity loop
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
			if (sub_state == Sub_state::write_client_key_exchange){
				write_client_key_exchange();
			}
			if (sub_state == Sub_state::write_client_finished){
				write_client_finished();
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

size_t Handshake_layer::write_content(void *d, size_t s){
    size_t result = write_record(Content_type::handshake, d, s);
	SHA::put(&hash_handshake_messages, (uint8_t*)d, result);	
	return result;
}

//Load decompless and decrypted handshake record body to "work_buffer".
//Return true when the work_buffer filled with more data than specified 
//in 1st argument.
bool Handshake_layer::load(size_t s){
	printf("handshake load\n");
	auto f = [&](void* b, size_t s) -> size_t {
		size_t result = read_record(Content_type::handshake, b, s);
		SHA::put(&hash_handshake_messages, (uint8_t*)b, result);	
		return result;
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

	SHA::init(&hash_handshake_messages);

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

    uint32_t base_time = hton32(time(NULL));
    *(uint32_t*)random_bytes = base_time;
	RNG::generate(NULL, random_bytes+4, 28);
	
	//Save client random.
	memcpy(client_server_random, random_bytes, 32);

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

bool Handshake_layer::write_client_key_exchange(){
	printf("w client key_exchange\n");

	//Create premaster secret
	//zero fill to ensure no imformation leak.
	uint8_t premaster_secret[48] = {
		0x03, 0x03 //client_version(TLS1.2)
	};
	RNG::generate(NULL, premaster_secret+2, 46);

	//Create master secret

	{
		static const char label[] = "master secret";
		SHA_PRF(premaster_secret, 48, 
				(uint8_t*)label, 13, 
				client_server_random, 64, 
				master_secret, 48);
	}

	{	
		static const char label[] = "key expansion";
		uint8_t in_buffer[64];//Server random + client random
		memcpy(in_buffer, client_server_random+32, 32);
		memcpy(in_buffer+32, client_server_random, 32);

		uint8_t out_buffer_len = 32+32+32+32;
		uint8_t out_buffer[out_buffer_len];
		SHA_PRF(master_secret, 48,
				(uint8_t*)label, 13,
				in_buffer, 64,
				out_buffer, out_buffer_len);
		uint8_t *ptr = out_buffer;
		memcpy(write_mac_key, ptr, 32); ptr +=32;
		memcpy(read_mac_key,  ptr, 32); ptr +=32;
		memcpy(write_encryption_key, ptr, 32); ptr +=32;
		memcpy(read_encryption_key,  ptr, 32);
		read_sequense_number = 0;
		write_sequense_number = 0;
	}

	
	size_t max_out_len = RSA::size(server_key);

	//memo: Premaster secret must be written as variable length field, 
	//      thus need length field.
	uint8_t out[4+2+max_out_len];
	uint8_t *out_premaster_secret_len = out + 4;
	uint8_t *out_premaster_secret = out + 4 + 2;

	ssize_t r_val = RSA::public_encrypt(
			server_key, 
			premaster_secret, 48, 
			out_premaster_secret, max_out_len);

	if (r_val == -1)
		return false;

	uint32_t total_len = hton32(r_val+2);

	//Handshake protocol header
	*(uint32_t*)out = total_len;
	out[0] = (uint8_t) Handshake_type::client_key_exchange;

	*(uint16_t*)out_premaster_secret_len = hton16(r_val);

    size_t result = 
		write_content(out, r_val+4+2);

	if (result != 0){
		Change_cipher_spec_layer::write_change_cipher_spec();
		set_state(State::process, Sub_state::write_client_finished);
		return true;
	}
	else{
		return false;
	}
}

bool Handshake_layer::write_client_finished(){
	printf("w client finish\n");
	uint8_t out[4+12] = {
		(uint8_t)Handshake_type::finished,
		0x00, 0x00, 0x0C //length
	};//header + content

	uint8_t *verify_data = out+4;

	uint8_t h[SHA::length];
	SHA::generate(&hash_handshake_messages, h);
	static const char label[] = "client finished";
	SHA_PRF(master_secret, 48,
			(uint8_t*)label, 15,
			h, SHA::length,
			verify_data, 12);

    size_t result = 
		write_content(out, 4+12);
	if (result != 0){
		set_state(State::read_header, Sub_state::read_server_finished);
		const char* dat = "hello world";
		write_record_block_cipher(Content_type::application_data,
				(void*)dat, strlen(dat));
		return true;
	}
	else{
		printf("client_finish fail");
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
	//Temporaly use client random as server random if invalid message sent
	//by the pear and discard it later.
	memcpy( client_server_random+32,
			reader.take_byte_pointer(32, client_server_random),
			32);

    //Session_id
	uint8_t session_id_length = reader.take<uint8_t>(0);
	for (int i= 0; i<session_id_length; i++)
		reader.skip<uint8_t>();

    //cipher_suite and complession method
	uint16_t cipher_suite = ntoh16(reader.take<uint16_t>(0));
	uint8_t compression_method = reader.take<uint8_t>(0);
	printf("cipher_suite = %x\n", cipher_suite);

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
		//print_hex((uint8_t*)certificate, length);

		uint8_t* begin = (uint8_t*)certificate;
		Certificate::Data *c = Certificate::from_binaly(begin, length);
		
		//todo: Use setter.
		server_key = Certificate::rsa_public_key(c);
		//X509* x509 = d2i_X509(NULL, &begin, length);

		//BIO* out_bio = BIO_new_fp(stdout, BIO_NOCLOSE);
		//X509_print(out_bio, x509);
		//BIO_free(out_bio);
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
