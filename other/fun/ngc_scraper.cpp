#include <chrono>
#include <cstdint>
#include <string>
#include <thread>
#include <vector>
#include <memory>
#include <atomic>
#include <exception>
#include <stdexcept>
#include <iostream>
#include <sstream>
#include <iomanip>

extern "C" {
#include "../../toxcore/DHT.h"
#include "../../toxcore/group_announce.h"
#include "../../toxcore/group_onion_announce.h"
#include "../../toxcore/logger.h"
#include "../../toxcore/mem.h"
#include "../../toxcore/mono_time.h"
#include "../../toxcore/network.h"
#include "../../toxcore/onion_announce.h"
#include "../../toxcore/forwarding.h"
}

static std::string to_hex(const uint8_t* data, size_t length) {
	std::ostringstream oss;
	oss << std::hex << std::setfill('0');
	for (size_t i = 0; i < length; ++i) {
		oss << std::setw(2) << static_cast<int>(data[i]);
	}
	return oss.str();
}

// an almost normal dht node
struct DHTNode {
	const Memory* _mem {os_memory()};
	const Network* _ns {os_network()};
	const Random* _rng {os_random()};
	std::unique_ptr<Logger, decltype(&logger_kill)> _logger {logger_new(_mem), logger_kill};
	//std::unique_ptr<Mono_Time, decltype(&mono_time_free)> _mono_time {mono_time_new(_mem, nullptr, nullptr), mono_time_free};
	Mono_Time* _mono_time {mono_time_new(_mem, nullptr, nullptr)};
	std::unique_ptr<DHT, decltype(&kill_dht)> _dht {nullptr, kill_dht};
	std::unique_ptr<Onion, decltype(&kill_onion)> _onion {nullptr, kill_onion};
	std::unique_ptr<Forwarding, decltype(&kill_forwarding)> _forwarding {nullptr, kill_forwarding};
	std::unique_ptr<GC_Announces_List, decltype(&kill_gca)> _gc_announces_list {nullptr, kill_gca};
	std::unique_ptr<Onion_Announce, decltype(&kill_onion_announce)> _onion_a {nullptr, kill_onion_announce};

	std::atomic<bool> _stop {false};

	DHTNode(
		const char* bootstrap_ip,
		uint16_t bootstrap_port,
		const uint8_t* bootstrap_pubkey
	) {
		IP ip;
		ip_init(&ip, true); // ipv6 enabled

		const uint16_t start_port = TOX_PORTRANGE_TO; // after normal range
		const uint16_t end_port = start_port + 10000; // just in case
		_dht.reset(new_dht(
			_logger.get(), _mem, _rng, _ns, _mono_time,
			new_networking_ex(_logger.get(), _mem, _ns, &ip, start_port, end_port, nullptr),
			true, false // no lan
		));

		_onion.reset(new_onion(_logger.get(), _mem, _mono_time, _rng, _dht.get()));
		_forwarding.reset(new_forwarding(_logger.get(), _mem, _rng, _mono_time, _dht.get()));
		_gc_announces_list.reset(new_gca_list(_mem));
		_onion_a.reset(new_onion_announce(_logger.get(), _mem, _rng, _mono_time, _dht.get()));

		gca_onion_init(_gc_announces_list.get(), _onion_a.get());

		if (!dht_bootstrap_from_address(
			_dht.get(),
			bootstrap_ip,
			true, //ipv6enabled,
			true, //dns_enabled,
			net_htons(bootstrap_port),
			bootstrap_pubkey
		)) {
			throw std::runtime_error("Failed to bootstrap");
		}
	}

	// we bootstrap all nodes off our first node
	DHTNode(
		const char* bootstrap_ip,
		uint16_t bootstrap_port,
		const uint8_t* bootstrap_pubkey,
		uint16_t& out_port,
		std::vector<uint8_t>& out_pubkey
	) : DHTNode(bootstrap_ip, bootstrap_port, bootstrap_pubkey) {
		out_port = net_ntohs(net_port(dht_get_net(_dht.get())));

		const uint8_t *const self_public_key = dht_get_self_public_key(_dht.get());
		// iterator constructor
		out_pubkey = {self_public_key, self_public_key+CRYPTO_PUBLIC_KEY_SIZE};
	}

	~DHTNode(void) {
		mono_time_free(_mem, _mono_time);
	}

	void iterate(void) {
		mono_time_update(_mono_time);

		do_dht(_dht.get());

		networking_poll(dht_get_net(_dht.get()), nullptr);

		//do_gca(_mono_time, _gc_announces_list.get());
	}

	bool is_dht_connected(void) {
		return dht_isconnected(_dht.get());
	}

	void run(void) {
		while (!_stop) {
			iterate();

			//std::this_thread::get_id();

			std::this_thread::sleep_for(std::chrono::milliseconds(
				20 + _rng->funcs->random_uniform(_rng->obj, 5)
			));
		}
	}

	void stop(void) {
		_stop = true;
	}
};

int main(int argc, char *argv[]) {
	// read number of nodes from args
	const int32_t num_nodes = (argc > 1) ? std::stoi(argv[1]) : 100;
	if (num_nodes <= 0) {
		throw std::invalid_argument("Number of nodes must be positive");
	}

	std::vector<std::unique_ptr<DHTNode>> nodes;
	std::vector<std::thread> threads;

	// tha lu
	const char* bootstrap_ip {"104.244.74.69"};
	uint16_t bootstrap_port {33445};
	const uint8_t bootstrap_pubkey[CRYPTO_PUBLIC_KEY_SIZE] {
		0x8E, 0x8B, 0x63, 0x29, 0x9B, 0x3D, 0x52, 0x0F,
		0xB3, 0x77, 0xFE, 0x51, 0x00, 0xE6, 0x5E, 0x33,
		0x22, 0xF7, 0xAE, 0x5B, 0x20, 0xA0, 0xAC, 0xED,
		0x29, 0x81, 0x76, 0x9F, 0xC5, 0xB4, 0x37, 0x25,
	};


	uint16_t firstnode_port;
	std::vector<uint8_t> firstnode_pubkey;

	std::cout << "Starting and bootstrapping node 0...\n";

	// start first node with remote bootstrap
	nodes.emplace_back(std::make_unique<DHTNode>(
		bootstrap_ip,
		bootstrap_port,
		bootstrap_pubkey,
		firstnode_port,
		firstnode_pubkey
	));

	std::cout << "node0 running at port " << firstnode_port << "\n";

	// wait for it to be bootstrapped
	while (true) {
		auto& node0 = nodes.back();

		node0->iterate();

		if (node0->is_dht_connected()) {
			std::cout << "node0 Connected to another bootstrap node successfully.\n";
			break;
		}

		std::this_thread::sleep_for(std::chrono::milliseconds(20));
	}

	// put node0 into thread
	threads.emplace_back(&DHTNode::run, nodes.back().get());

	std::cout << "Sleeping while node0 populates nodes\n";
	// wait 15sec on the main thread for node0 to populate peers
	std::this_thread::sleep_for(std::chrono::seconds(15));

	// start the rest with first node as bootstrap
	for (int32_t i = 1; i < num_nodes; i++) {
		nodes.emplace_back(std::make_unique<DHTNode>(
			"127.0.0.1",
			firstnode_port,
			firstnode_pubkey.data()
		));
		threads.emplace_back(&DHTNode::run, nodes.back().get());

		// offset nodes sleep timing
		std::this_thread::sleep_for(std::chrono::milliseconds(77));
	}

	std::cout << "Running " << num_nodes << " DHT nodes. Press Enter to stop...\n";
	std::cin.get();

	for (auto& node : nodes) {
		node->stop();
	}

	for (auto& thread : threads) {
		if (thread.joinable()) {
			thread.join();
		}
	}

	for (size_t i = 0; i < nodes.size(); i++) {
		GC_Announces* announces = nodes[i]->_gc_announces_list->root_announces;

		while (announces != nullptr) {
			std::cout << "node " << i << " saw: " << to_hex(announces->chat_id, CHAT_ID_SIZE) << "\n";

			for (size_t i = 0; i < GCA_MAX_SAVED_ANNOUNCES_PER_GC; i++) {
				auto& peer = announces->peer_announces[i];
				if (peer.timestamp == 0) {
					continue;
				}

				std::cout << "  peer: " << to_hex(peer.base_announce.peer_public_key, ENC_PUBLIC_KEY_SIZE) << "\n";

				if (peer.base_announce.ip_port_is_set) {
					Ip_Ntoa ip_str;
					const char* ip_port_str = net_ip_ntoa(&peer.base_announce.ip_port.ip, &ip_str);
					std::cout << "    ip+port: " << ip_port_str << " : " << net_ntohs(peer.base_announce.ip_port.port) << "\n";
				}

				if (peer.base_announce.tcp_relays_count > 0) {
					Ip_Ntoa ip_str_buff;
					const char* ip_str = net_ip_ntoa(&peer.base_announce.tcp_relays[0].ip_port.ip, &ip_str_buff);
					std::cout << "    tcp_relays: " << ip_str << " : " << net_ntohs(peer.base_announce.tcp_relays[0].ip_port.port) << " pubkey: " << to_hex(peer.base_announce.tcp_relays[0].public_key, CRYPTO_PUBLIC_KEY_SIZE) << "\n";
				}
			}

			announces = announces->next_announce;
		}
	}

	return 0;
}

