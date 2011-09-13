#pragma once

#include <sha1.h>
#include <string>

#define TSUP_FLAG 128
#define NO_ID -1

std::string b2a(long long v, const char* postfix = NULL);
std::string backward_slashes(std::string);
std::string duration2a(float);
std::string escape_string(const std::string&);
std::string forward_slashes(std::string);
std::string generate_random_string(int);
std::string get_env(const std::string&);
int hms2i(int h, int m, int s);
bool is_private_ipa(int a);
int merkle_tree_size(int v);
std::string n(long long);
std::string native_slashes(const std::string&);
std::string hex_decode(const std::string&);
std::string hex_encode(int l, int v);
std::string hex_encode(const_memory_range);
std::string hex_encode_spaces(const_memory_range);
std::string js_encode(const std::string&);
std::string peer_id2a(const std::string&);
std::string time2a(time_t);
std::string uri_decode(const std::string&);
std::string uri_encode(const std::string&);
int xbt_atoi(const std::string&);
std::string xbt_version2a(int);

inline long long htonll(long long v)
{
	const unsigned char* a = reinterpret_cast<const unsigned char*>(&v);
	long long b = a[0] << 24 | a[1] << 16 | a[2] << 8 | a[3];
	return b << 32 | static_cast<long long>(a[4]) << 24 | a[5] << 16 | a[6] << 8 | a[7];
}

inline long long ntohll(long long v)
{
	return htonll(v);
}

inline bool logic_xor(bool a, bool b)
{
	return a && !b || !a && b;
}

enum
{
	hs_name_size = 0,
	hs_name = 1,
	hs_reserved = 20,
	hs_info_hash = 28,
	hs_size = 48,
};

enum
{
	uta_connect		= 0,
	uta_announce	= 1,
	uta_scrape		= 2,
	uta_error		= 3,

	//*_ TSUP packets
	uta_syn			= 128,
	uta_hello		= 129,
	uta_summary		= 130,
	uta_update		= 131,
	uta_candidature = 132,
	uta_leader		= 133,

};

enum
{
	uti_connection_id = 0,
	uti_action = 8,
	uti_transaction_id = 12,
	uti_size = 16,

	utic_size = 16,

	utia_info_hash = 16,
	utia_peer_id = 36,
	utia_downloaded = 56,
	utia_left = 64,
	utia_uploaded = 72,
	utia_event = 80,
	utia_ipa = 84,
	utia_key = 88,
	utia_num_want = 92,
	utia_port = 96,
	utia_size = 98,

	utis_size = 16,

	uto_action = 0,
	uto_transaction_id = 4,
	uto_size = 8,

	utoc_connection_id = 8,
	utoc_size = 16,

	utoa_interval = 8,
	utoa_leechers = 12,
	utoa_seeders = 16,
	utoa_size = 20,

	utos_size = 8,

	utoe_size = 8,

	//*_ Common size of all TSUP packets
	ut_tsup_size = 18,
	ut_port = 16,

	//*_ TSUP packet header sizes
	ut_syn_size = ut_tsup_size + 1,
	ut_hello_size = ut_tsup_size,
	ut_summary_size = ut_tsup_size,
	ut_update_size = ut_tsup_size + 1,	//*_ last byte contains flags
	ut_candidature_size = ut_tsup_size + 1,	//*_ last byte contains flags
	ut_leader_size = ut_tsup_size + 1,	 //*_ last byte contains flags

	ut_syn_flags = ut_tsup_size,
	ut_update_flags = ut_tsup_size,
	ut_candidature_flags = ut_tsup_size,
	ut_leader_flags = ut_tsup_size,
};

#define UPDATE_PEER_SIZE 7

/**
 *_ SYN packet flags
 */
enum
{
	FL_SYN_NORMAL = 0,

	FL_SYN_ACK = 1,
};

/**
 *_ UPDATE packet flags
 */
enum
{
	FL_UPDATE_NORMAL = 0,

	FL_UPDATE_ACK = 1,
	FL_UPDATE_SUMMARY = 2,
	FL_UPDATE_BOR = 4,	//*_ border tracker
};

/**
 *_ UPDATE packet flags for each peer
 */
enum
{
	FL_UPDATE_PEER_NEG = 1,
};

/**
 *_ SUMMARY packet swarm flags
 */
enum
{
	FL_SUMMARY_FILE_POS = 0,
	FL_SUMMARY_FILE_NEG = 1,
	FL_SUMMARY_FILE_BOR = 4,	//*_ border tracker
};

/**
 *_ CANDIDATURE packet flags
 */
enum
{
	FL_CANDIDATURE_ACK = 1,
};

/**
 *_ LEADER packet flags
 */
enum
{
	FL_LEADER_ACK = 1,
};

enum enum_transactions
{
	TR_CONNECT = 0,
	TR_UNIFY = 1,
	TR_UPDATE = 2,
	TR_CANDIDATURE = 3,
	TR_LEADER = 4,
};
