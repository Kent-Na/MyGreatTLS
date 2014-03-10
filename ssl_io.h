#include "openssl.cpp"

//non_blocking ssl layer
//

namespace ssl{

using namespace openssl;

//See section 5.2.1

constexpr size_t initial_buffer_size = 1024*4;

enum class Content_type: uint8_t{
    change_cipher_spec = 20,
    alert              = 21,
    handshake          = 22,
    application_data   = 23,
};

enum class Alert_level: uint8_t{
    warning = 1,
    fatal   = 2,
};

enum class Alert_messages: uint8_t{
    close_notify            = 0,
    unexpected_message      = 10, //fatal
    bad_record_mac          = 20, //fatal
//  decryption_failed       = 21, //RESERVED
    record_everflow         = 22, //fatal
    decempression_failure   = 30, //fatal
    handshake_failure       = 40, //fatal
//  no_certificate          = 41, //RESERVED
    bad_certificate         = 42,
    unsupported_certificate = 43,
    certificate_revoked     = 44,
    certificate_expired     = 45,
    certificate_unknown     = 46,
    illiegal_parameter      = 47, //fatal
    unknown_ca              = 48, //fatal
    access_denied           = 49, //fatal
    decode_error            = 50, //fatal
    decrypt_error           = 51, //fatal
//  export_restriction      = 60, //RESERVED
    protocol_version        = 70, //fatal
    insufficient_security   = 71, //fatal
    internal_error          = 80, //fatal
    user_canceled           = 90,
    no_renegotiation        = 100,
    unsupported_extension   = 110, //fatal
};

enum class Handshake_type: uint8_t{
    hello_request       = 0,
    client_hello        = 1,
    server_hello        = 2,
    certificate         = 11,
    server_key_exchange = 12,
    certificate_request = 13,
    server_done         = 14,
    certificate_verify  = 15,
    client_key_exchange = 16,
    finished            = 20,
};

class Record_event_layer;
class Change_cipher_spec_layer;
class Handshake_layer;

class Record_io_layer: public Io_layer{
	friend Record_event_layer;
	friend Change_cipher_spec_layer;
	friend Handshake_layer;
    enum class State: uint8_t{
        read_header,
        read_fragment,
		read_fragment_from_buffer
    };


    struct Record_header{
        Content_type content_type;
        uint8_t      major_version;
        uint8_t      minor_version;
        uint16_t     length;
    };

    Record_header record_header;
	size_t remain_fragment_size;
    State state;
	
	//todo: dealt with wrap around.
	uint64_t write_sequense_number;
	uint8_t write_mac_key[32];
	uint8_t write_encryption_key[32];
	uint8_t write_encrypt;//temporal implementation
	uint64_t read_sequense_number;
	uint8_t read_mac_key[32];
	uint8_t read_encryption_key[32];
	uint8_t read_encrypt;//temporal implementation

	rcp::buffer<> work_buffer;
	
	bool read_record_header();
    size_t read_record(Content_type type, void* v, size_t s);
    size_t read_record_fragment(void* v, size_t s);
    size_t read_record_fragment_block_cipher(void* v, size_t s);
    size_t read_record_fragment_bufferd(void* v, size_t s);

    //Write on ssl
    //Write operation to ssl layer should succeed to write whole data,
    //or compleataly fail and no data are written at all.
    //It will never partialy write thus return value are ether 0 or
    //length of data.
    //Exseeded TLS record size rimit will never success.
    size_t write_record(Content_type type, void* v, size_t s);

    size_t write_record_plane(Content_type type, void* v, size_t s);
    size_t write_record_block_cipher(Content_type type, void* v, size_t s);

	bool load(size_t size);
	void set_state(State new_state);
	void internal_error(const char* err_message);

	//todo: remove fatal frag from args.
	void alert(Alert_messages, bool fatal);
	public:
	Record_io_layer();
	~Record_io_layer();
};

class Change_cipher_spec_layer: public Record_io_layer{
	friend Handshake_layer;
	friend Record_event_layer;
	void read_change_cipher_spec();
	void write_change_cipher_spec();
    void read_ready();
    void write_ready();
};

class Handshake_layer: public Change_cipher_spec_layer{
	friend Record_event_layer;
    enum class State{
        read_header,
        read_body,
        process,
    };

    enum class Sub_state: uint8_t{
        write_client_hello,
        read_server_hello,
		read_certificate,
		read_server_hello_done,
		write_client_key_exchange,
		write_client_hello_done,
		write_client_finished,
		read_server_finished,

        read_client_hello,
        write_server_hello,
        read_finished,
        write_finished,
        handshake_done,
    };
    
    //Handshake header
    struct Header{
        Handshake_type msg_type;
        uint32_t length;//uint24 in spec
    };

    Header header;
    State state;
    Sub_state sub_state;
	rcp::buffer<> work_buffer;
	//First 32 bytes are client.random. Last 32 are server.random.
	uint8_t client_server_random[64];
	uint8_t master_secret[48];
	SHA::State hash_handshake_messages;
	RSA::Data* server_key;

	void set_state(State s, Sub_state ss);
	bool load(size_t s);
    size_t read_content(void* v, size_t s);
    size_t write_content(void* v, size_t s);

	void proceed();
	void start_server_handshake();
	void start_client_handshake();
	bool write_client_hello();
	bool write_client_key_exchange();
	bool write_client_finished();
	void process_server_hello();
	void process_certificate();
	void process_client_hello();
	void process_server_hello_done();
	bool read_handshake_header();
	bool load_handshake_body();
    bool load_handshake(Handshake_type* type);

    void read_ready();
    void write_ready();
	public:
	Handshake_layer();
	~Handshake_layer();
};

class Record_event_layer: public Handshake_layer{
	bool is_connected();
	void proceed();
	void low_level_read_ready();
	void low_level_write_ready();
public:
	void connect();
};

}

using Ssl_layer = ssl::Record_event_layer;
