
///////////////
//All function must be thread safe with different state value.


class Rng_abstruct{
	using state_type = void*;

	static void 
		init(state_type state);
	static void 
		deinit(state_type state);
	static void 
		generate(state_type state, uint8_t* output, size_t output_len);
	static void
		inject(state_type state, uint8_t* data, size_t data_len);
};

class Hash_abstruct{
	using state_type = void*;
	constexpr size_t hash_length = 32;

	static void init(state_type state);
	static void deinit(state_type state);
	static void update(state_type state, uint8_t* data, size_t data_len);
	static void finish(state_type state, uint8_t* data);
};

class Block_crypt_abstruct{
	using state_type = void*;

	static void init(state_type state);
	static void deinit(state_type state);

	static size_t
		decrypt(state_type state, uint8_t* input, size_t input_len
				uint8_t* output, size_t output_len);

	static size_t
		encrypt(state_type state, uint8_t* input, size_t input_len
				uint8_t* output, size_t output_len);
};

class Certificate_abstruct{
	using Certificate = void*;

	static Certificate from_X509_binaly(uint8_t data, size_t data_len);
};
