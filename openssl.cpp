#include <openssl/objects.h>
#include <openssl/x509.h>
#include <openssl/rand.h>
#include <openssl/aes.h>

namespace ssl{

namespace openssl{

struct RSA{
	using Data = ::RSA;

	static size_t size(Data *data);

	static ssize_t
		public_encrypt(Data *data, uint8_t *input, size_t input_len,
				uint8_t *output, size_t output_len);

	static ssize_t
		private_decrypt(Data *data, uint8_t *input, size_t input_len,
				uint8_t *output, size_t output_len);
};

struct SHA{
	static void hash(uint8_t *input, size_t input_len);

	using State = SHA256_CTX;
	static constexpr size_t length = 32;

	static void init(State *state);
	static void put(State *state, uint8_t *input, size_t input_len);
	static void generate(State *state, uint8_t *output);
	static void hash(
		State *state, uint8_t *input, size_t input_len, uint8_t *output);
};

struct Certificate{
	using Data = X509;
	static Data* from_binaly(const uint8_t *input, size_t input_len);
	static RSA::Data* rsa_public_key(Data *data);
};

//memo: Must be replaced by thread safe variant.
struct RNG{
	using State = void*;//dummy
	static void generate(State s, uint8_t *output, size_t output_len);
};


};

namespace openssl{

void SHA::init(State *state){
	SHA256_Init(state);
}
void SHA::put(State *state, uint8_t* input, size_t input_len){
	SHA256_Update(state, (void*)input, input_len);
}
void SHA::generate(State *state, uint8_t* output){
	SHA256_Final(output, state);
}
void SHA::hash(
	State *state, uint8_t *input, size_t input_len, uint8_t *output){
	SHA::init(state);
	SHA::put(state, input, input_len);
	SHA::generate(state, output);
}

Certificate::Data* Certificate::from_binaly(
		const uint8_t* input, size_t input_len){
	return d2i_X509(NULL, &input, input_len);
}

size_t RSA::size(Data *data){
	return RSA_size(data);
}

RSA::Data* Certificate::rsa_public_key(Data *data){
	EVP_PKEY* public_key = X509_get_pubkey(data);
	RSA::Data* rsa = EVP_PKEY_get1_RSA(public_key);
	EVP_PKEY_free(public_key);
	return rsa;
}

void RNG::generate(State s, uint8_t *output, size_t output_len){
	int r_val = RAND_bytes(output, output_len);
}


ssize_t RSA::public_encrypt(
		Data *data, uint8_t* input, size_t input_len,
		uint8_t* output, size_t output_len){
	return RSA_public_encrypt(
			input_len, input, output, data, RSA_PKCS1_PADDING);

}

ssize_t RSA::private_decrypt(
		Data *data, uint8_t* input, size_t input_len,
		uint8_t* output, size_t output_len){
	return RSA_private_decrypt(
			input_len, input, output, data, RSA_PKCS1_PADDING);
}


}
}


