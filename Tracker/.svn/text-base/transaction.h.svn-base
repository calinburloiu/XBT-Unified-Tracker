#pragma once

#include "server.h"

//struct t_tracker;
//struct tracker_key;
//class Cserver;

/**
 * Handles the UDP communication with a client.
 */
class Ctransaction
{
public:
	long long connection_id() const;
	void recv();
	void send(const_memory_range);
	void send(const_memory_range, const sockaddr_in &a);
	void send_announce(const_memory_range);
	void send_connect(const_memory_range);
	void send_scrape(const_memory_range);
	void send_error(const_memory_range, const std::string& msg);

	//*_ TSUP send & process functions
	void process_syn(const_memory_range, Cserver::t_tracker& tracker);
	void process_syn_ack(const_memory_range, Cserver::t_tracker& tracker);
	void process_hello(const_memory_range, Cserver::t_tracker& tracker);
	void process_summary(const_memory_range, Cserver::t_tracker& tracker);
	void process_update(const_memory_range, Cserver::t_tracker& tracker);
	void process_candidature(const_memory_range, Cserver::t_tracker& tracker);
	void process_leader(const_memory_range, Cserver::t_tracker& tracker);
	void make_header(char *output, long long connection_id, int transaction_id, int action);
	void send_syn(long long connection_id, int transaction_id, const sockaddr_in &a, unsigned flags);
	void send_hello(long long connection_id, const sockaddr_in &a);
	void send_summary(Cserver::t_tracker& tracker, const sockaddr_in &a);
	void send_summary(long long connection_id, int transaction_id, const sockaddr_in &a, std::string payload);
	void send_update(long long connection_id, int transaction_id, const sockaddr_in &a, std::string payload, unsigned char flags);
	void send_candidature(long long connection_id, int transaction_id, const sockaddr_in &a, int mandates, unsigned char flags);
	void send_leader(long long connection_id, int transaction_id, const sockaddr_in &a, std::string payload, unsigned char flags);

	Ctransaction(Cserver&, const Csocket&);
private:
	Cserver& m_server;
	Csocket m_s;
	sockaddr_in m_a;
};
