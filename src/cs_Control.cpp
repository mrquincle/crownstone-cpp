#include <iostream>
#include <iomanip>
#include <blepp/blestatemachine.h>
#include <blepp/pretty_printers.h>
#include <unistd.h>
#include <packet.h>
#include <aes.hpp>

using namespace std;
using namespace chrono;
using namespace BLEPP;

int main(int argc, char **argv)
{
	log_level = Error;

	int c;
	string help = R"X(-[h]:
  -h  show this message
)X";

	opterr = 0;

	string address;
	uint8_t value;
	string key_s;

	while((c=getopt(argc, argv, "!a:!v:!k:h")) != -1)
	{
		switch(c) {
		case 'a':
			address = string(optarg);
			break;
		case 'v':
			value = atoi(optarg);
			break;
		case 'k':
			key_s = string(optarg);
			break;
		case 'h':
			cout << "Usage: " << argv[0] << " " << help;
			return 0;
		case '?':
			if (optopt == 'k') {
				cerr << "Option k requires an argument (key)" << endl;
			}
			return 1;
		default:
			cerr << argv[0] << ":  unknown option " << c << endl;
			return 1;
		}
	}
	if (key_s.size() != 32) {
		cout << "Key should be present and have 16 digits (size = " << key_s.size() << ")" << endl;
		return 1;
	}

	uint8_t key[16] = {};
	std::stringstream ss;

	for(int i = 0; i < key_s.size(); i+=2) {
		ss << std::hex << key_s.substr(i,2);
		int byte;
		ss >> byte;
		key[i/2] = byte & 0xFF;
		ss.str(std::string());
		ss.clear();
	}
	for (int i = 0; i < 16; i++) {
		cout << to_hex(key[i]);
	}
	cout << endl;

	BLEGATTStateMachine gatt;

	struct AES_ctx ctx;
	AES_init_ctx(&ctx, key);

	std::function<void()> found_services_and_characteristics_cb = [&gatt, &value, &ctx](){

		uint8_t protocol;
		uint8_t validation_key[4];
		uint8_t nonce[5];

		for(auto& service: gatt.primary_services) {
			for(auto& characteristic: service.characteristics) {
				if(characteristic.uuid == UUID(uuid_session)) {
				    cout << "Found service UUID: " << to_str(characteristic.uuid) << endl;
					characteristic.cb_read = [&](const PDUReadResponse& r) {
						auto val = r.value();
						auto len = val.second - val.first;

						uint8_t data[16];
						memset(data, 0, 16);
						memcpy(data, val.first, len);
						
						cout << "Encrypted data: ";
						cout << setfill('0');
						for (int i = 0; i < len; ++i) {
							cout << std::hex << setw(2) << (int)data[i] << ' ';
						}
						cout << endl;

						AES_ECB_decrypt(&ctx, data);
						
						cout << "Decrypted data: ";
						cout << setfill('0');
						for (int i = 0; i < len; ++i) {
							cout << std::hex << setw(2) << (int)data[i] << ' ';
						}
						cout << endl;

						session_packet *pck = (session_packet*)data;

						protocol = pck->protocol;
						for (int i = 0; i < 5; ++i) {
							nonce[i] = pck->nonce[i];
						}
						for (int i = 0; i < 4; ++i) {
							validation_key[i] = pck->validation_key[i];
						}

						cout << "Validation: " << pck->validation << endl;
						cout << "Protocol: " << (int)pck->protocol << endl;
						cout << setfill('0');
						cout << "Nonce: ";
						for (int i = 0; i < 5; ++i) {
							cout << std::hex << setw(2) << (int)pck->nonce[i] << ' ';
						}
						cout << endl;
						cout << "Validation key: ";
						for (int i = 0; i < 4; ++i) {
							cout << std::hex << setw(2) << (int)pck->validation_key[i] << ' ';
						}
						cout << endl;
						//gatt.close();
					};

					//cout << "Go to next" << endl;
					characteristic.read_request();
					goto done;
				}
			}
		}
done:
		gatt.read_and_process_next();

		srand(time(NULL));
		uint8_t iv[16];
		memset(iv, 0, 16);
		// cntr
		for (int i = 0; i < 3; ++i) {
			iv[i] = 0;
		}
		for (int i = 0; i < 5; ++i) {
			iv[i+3] = nonce[i];
		}

		AES_ctx_set_iv(&ctx, iv);

		for(auto& service: gatt.primary_services) {
			for(auto& characteristic: service.characteristics) {
				if(characteristic.uuid == UUID(uuid_control)) {
				    cout << "Found service UUID: " << to_str(characteristic.uuid) << endl;

					uint8_t header_size = 4;
					uint8_t data[16 + header_size];
					memset(data, 0, 16 + header_size);

					control_packet *pkt = (control_packet*)data;
					for (int i = 0; i < 3; ++i) {
						pkt->nonce[i] = iv[i];
					}
					pkt->user_level = 2;
					for (int i = 0; i < 4; ++i) {
						pkt->validation_key[i] = validation_key[i];
					}
					pkt->protocol = protocol;
					pkt->type = 20;
					pkt->size = 1;
					pkt->value[0] = 100;

					assert(sizeof(control_packet) == 16 + 4);
					
					AES_CTR_xcrypt_buffer(&ctx, data + 4, 16);

					characteristic.write_command(data, 16 + 4);
				}
			}
		}
	};


	gatt.setup_standard_scan(found_services_and_characteristics_cb);

	gatt.cb_disconnected = [](BLEGATTStateMachine::Disconnect d) {
		cerr << "Disconnect for reason " << BLEGATTStateMachine::get_disconnect_string(d) << endl;
		exit(1);
	};

	cout << "Connect to device " << address << endl;
	bool blocking = true;
	bool pubaddr = false;
	gatt.connect(address, blocking, pubaddr);

	try {
		for(;;) {
			gatt.read_and_process_next();
		}
	} catch(std::runtime_error e) {
		cerr << "Something's stopping bluetooth working: " << e.what() << endl;
	} catch(std::logic_error e) {
		cerr << "Oops, someone fouled up: " << e.what() << endl;
	}

}
