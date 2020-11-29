#pragma once

#include <string>

std::string uuid_session = "24f0000e-7d10-4805-bfc1-7663a01c3bff";
std::string uuid_control = "24f0000c-7d10-4805-bfc1-7663a01c3bff";
std::string uuid_result  = "24f0000d-7d10-4805-bfc1-7663a01c3bff";

// control_packet cmd;
// cmd.protocol = 0;
// cmd.type = 22;
// cmd.size = 1;
// cmd.value = value;
//
typedef struct  __attribute__((__packed__)) control_packet {
	uint8_t nonce[3];
	uint8_t user_level;
	// encrypt from here on
	uint8_t validation_key[4];
	uint8_t protocol;
	uint16_t type;
	uint16_t size;
	uint8_t value[16-(4+1+2+2)];
} control_packet;

typedef struct  __attribute__((__packed__)) session_packet {
	uint32_t validation;
	uint8_t protocol;
	uint8_t nonce[5];
	uint8_t validation_key[4];
	uint8_t padding[2];
} session_packet;

typedef uint8_t cs_ret_code_t;
typedef uint8_t* cs_data_t;
typedef size_t cs_buffer_size_t;

/**
 * Encrypt data with given key in ECB mode.
 *
 * The data that's encrypted is a concatenation of prefix and input.
 *
 * @param[in]  key                 Key to encrypt with.
 * @param[in]  prefix              Extra data to put before the input data. Can be skipped by passing a null pointer and data size 0.
 * @param[in]  input               Input data to be encrypted.
 * @param[out] output              Buffer to encrypt to. Can be the same as input, as long as: output pointer >= input pointer + prefix size.
 * @param[out] writtenSize         How many bytes are written to output.
 * @return                         Return code.
 */
cs_ret_code_t encryptEcb(cs_data_t key, cs_data_t prefix, cs_data_t input, cs_data_t output, cs_buffer_size_t& writtenSize);

