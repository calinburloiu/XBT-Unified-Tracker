#include "stdafx.h"
#include "transaction.h"

#include <bt_misc.h>
#include <bt_strings.h>
#include <iostream>
#include <sha1.h>
#include <stream_int.h>


Ctransaction::Ctransaction(Cserver& server, const Csocket& s):
	m_server(server)
{
	m_s = s;
}

long long Ctransaction::connection_id() const
{
	const int cb_s = 12;
	char s[cb_s];
	write_int(8, s, m_server.secret());
	write_int(4, s + 8, m_a.sin_addr.s_addr);
	char d[20];
	(Csha1(const_memory_range(s, cb_s))).read(d);
	return read_int(8, d);
}

void Ctransaction::recv()
{
	const int cb_b = 2 << 10;
	char b[cb_b];
	while (1)
	{
		int action;
		socklen_t cb_a = sizeof(sockaddr_in);
		int r;
		Cserver::t_tracker *tracker = NULL;

		memset(&m_a, 0, sizeof(sockaddr_in));
		r = m_s.recvfrom(memory_range(b, cb_b), reinterpret_cast<sockaddr*>(&m_a), &cb_a);
		if (r == SOCKET_ERROR)
		{
			if (WSAGetLastError() != WSAEWOULDBLOCK)
				std::cerr << "recv failed: " << Csocket::error2a(WSAGetLastError()) << std::endl;
			return;
		}
		//else
			//cout << "Am primit datagrama:\n";

		// ** Check the minimum size of a packet
		if (r < uti_size)
		{
			cout << "uti_size fail\n";
			return;
		}

		// ** Packet action (type)
		action = read_int(4, b + uti_action, b + r);
		//cout << inet_ntoa(m_a.sin_addr) << " " << ntohs(m_a.sin_port) << endl;//DEB

		//*_ Common behavior part for all TSUP packets received.
		if(action & TSUP_FLAG)
		{
			//*_ Get tracker source port from the transaction_id
			int port = read_int(2, b + ut_port, b + r);
			//m_a.sin_port = htons(port);

			//*_ Get the tracker associated with the host&port of the received packet.
			tracker = m_server.tracker(m_a.sin_addr.s_addr, port);
			if(tracker == NULL)
			{
				cout << "tracker not in list\n";
				return;		//*_ drop the packet if the tracker is not on the list
			}

			//*_ If the tracker uses NAT, update its nat_port
			tracker->nat_port = ntohs(m_a.sin_port);
		}

		switch (action)
		{
		// ** UDP Tracker packets
		case uta_connect:
			if (r >= utic_size)
				send_connect(const_memory_range(b, r));
			break;
		case uta_announce:
			if (r >= utia_size)
				send_announce(const_memory_range(b, r));
			break;
		case uta_scrape:
			if (r >= utis_size)
				send_scrape(const_memory_range(b, r));
			break;

		//*_ TSUP packets
		case uta_syn:
			process_syn(const_memory_range(b, r), *tracker);
			break;
		case uta_hello:
			process_hello(const_memory_range(b, r), *tracker);
			break;
		case uta_summary:
			process_summary(const_memory_range(b, r), *tracker);
			break;
		case uta_update:
			process_update(const_memory_range(b, r), *tracker);
			break;
		case uta_candidature:
			process_candidature(const_memory_range(b, r), *tracker);
			break;
		case uta_leader:
			process_leader(const_memory_range(b, r), *tracker);
			break;

		default:	//DEB
			std::cout << "transaction.cpp: recv default\n";
		}
	}
}

void Ctransaction::send_connect(const_memory_range r)
{
	if (!m_server.config().m_anonymous_connect)
		return;
	if (read_int(8, r + uti_connection_id, r.end) != 0x41727101980ll)
		return;
	const int cb_d = 2 << 10;
	char d[cb_d];
	write_int(4, d + uto_action, uta_connect);
	write_int(4, d + uto_transaction_id, read_int(4, r + uti_transaction_id, r.end));
	write_int(8, d + utoc_connection_id, connection_id());
	send(const_memory_range(d, utoc_size));
}

void Ctransaction::send_announce(const_memory_range r)
{
	cout << "*** send_announce (transaction.cpp)\n";//DEB
	if (read_int(8, r + uti_connection_id, r.end) != connection_id())
		return;
	if (!m_server.config().m_anonymous_announce)
	{
		send_error(r, "access denied");
		return;
	}
	Ctracker_input ti;
	ti.m_downloaded = read_int(8, r + utia_downloaded, r.end);
	ti.m_event = static_cast<Ctracker_input::t_event>(read_int(4, r + utia_event, r.end));
	ti.m_info_hash.assign(reinterpret_cast<const char*>(r + utia_info_hash), 20);
	ti.m_ipa = read_int(4, r + utia_ipa, r.end) && is_private_ipa(m_a.sin_addr.s_addr)
		? htonl(read_int(4, r + utia_ipa, r.end))
		: m_a.sin_addr.s_addr;
	ti.m_left = read_int(8, r + utia_left, r.end);
	ti.m_num_want = read_int(4, r + utia_num_want, r.end);
	ti.m_peer_id.assign(reinterpret_cast<const char*>(r + utia_peer_id), 20);
	ti.m_port = htons(read_int(2, r + utia_port, r.end));
	ti.m_uploaded = read_int(8, r + utia_uploaded, r.end);
	std::string error = m_server.insert_peer(ti, true, NULL);
	if (!error.empty())
	{
		send_error(r, error);
		return;
	}
	const Cserver::t_file* file = m_server.file(ti.m_info_hash);
	if (!file)
		return;
	const int cb_d = 2 << 10;
	char d[cb_d];
	write_int(4, d + uto_action, uta_announce);
	write_int(4, d + uto_transaction_id, read_int(4, r + uti_transaction_id, r.end));
	write_int(4, d + utoa_interval, m_server.config().m_announce_interval);
	write_int(4, d + utoa_leechers, file->leechers);
	write_int(4, d + utoa_seeders, file->seeders);
	std::string peers = file->select_peers(ti);
	memcpy(d + utoa_size, peers.data(), peers.size());
	send(const_memory_range(d, d + utoa_size + peers.size()));
}

void Ctransaction::send_scrape(const_memory_range r)
{
	if (read_int(8, r + uti_connection_id, r.end) != connection_id())
		return;
	if (!m_server.config().m_anonymous_scrape)
	{
		send_error(r, "access denied");
		return;
	}
	const int cb_d = 2 << 10;
	char d[cb_d];
	write_int(4, d + uto_action, uta_scrape);
	write_int(4, d + uto_transaction_id, read_int(4, r + uti_transaction_id, r.end));
	char* w = d + utos_size;
	for (r += utis_size; r + 20 <= r.end && w + 12 <= d + cb_d; r += 20)
	{
		if (const Cserver::t_file* file = m_server.file(r.sub_range(0, 20).string()))
		{
			w = write_int(4, w, file->seeders);
			w = write_int(4, w, file->completed);
			w = write_int(4, w, file->leechers);
		}
		else
		{
			w = write_int(4, w, 0);
			w = write_int(4, w, 0);
			w = write_int(4, w, 0);
		}
	}
	m_server.stats().scraped_udp++;
	send(const_memory_range(d, w));
}

void Ctransaction::send_error(const_memory_range r, const std::string& msg)
{
	const int cb_d = 2 << 10;
	char d[cb_d];
	write_int(4, d + uto_action, uta_error);
	write_int(4, d + uto_transaction_id, read_int(4, r + uti_transaction_id, r.end));
	memcpy(d + utoe_size, msg.data(), msg.size());
	send(const_memory_range(d, utoe_size + msg.size()));
}

void Ctransaction::send(const_memory_range b, const sockaddr_in &a)
{
	if (m_s.sendto(b, reinterpret_cast<const sockaddr*>(&a), sizeof(sockaddr_in)) != b.size())
		std::cerr << "send failed: " << Csocket::error2a(WSAGetLastError()) << std::endl;
}

inline void Ctransaction::send(const_memory_range b)
{
	send(b, m_a);
}


/*____________TSUP send & process functions______________
 *
 */

/**
 *_ Take the appropriate action if a SYN packet is received.
 */
void Ctransaction::process_syn(const_memory_range b, Cserver::t_tracker& tracker)
{
	//*_ flags
	unsigned char flags = read_int(1, b + ut_update_flags, b.end);
	if(flags & FL_SYN_ACK)
	{
		process_syn_ack(b, tracker);
		return;
	}

	//*_ transaction_id
	tracker.input_transaction_ids[TR_CONNECT] = read_int(4, b + uti_transaction_id, b.end);

	cout << "* Recv  :\t" << Csocket::inet_ntoa(tracker.host) << "\t" << (::time(NULL) % 100) << "\tSYN\n";//DEB
	//*_ status
	tracker.status = Cserver::ST_SYN;
	//cout << Cserver::ST_SYN << " " << Cserver::ST_PENDING << " " << tracker.status << endl;
	printStatus(tracker);//DEB

	// TODO: connection_id changed. Should I flush?
	//*_ connection_id
	long long recv_connection_id = read_int(8, b + uti_connection_id, b.end);
	if(tracker.connection_id == NO_ID || recv_connection_id != tracker.connection_id)
		tracker.connection_id = connection_id();

	//*_ recv_time
	tracker.recv_time = ::time(NULL);

	//*_ clear buffers
	tracker.clear();

	//*_ Send SYN-ACK
	send_syn(tracker.connection_id, tracker.input_transaction_ids[TR_CONNECT], m_a, FL_SYN_ACK);
}

/**
 *_ Take the appropriate action if a SYN packet with flag ACK is received.
 */
void Ctransaction::process_syn_ack(const_memory_range b, Cserver::t_tracker& tracker)
{
	//*_ status
	if(tracker.status != Cserver::ST_DISCONNECTED &&
			tracker.status != Cserver::ST_PENDING)
		return;			//*_ Drop it if connected
	if(tracker.status & Cserver::ST_SYN)	//*_ Close connection, delay next SYN, drop packet
	{
		tracker.status = Cserver::ST_DISCONNECTED | Cserver::ST_PENDING;
		tracker.delay = m_server.generate_delay();
		return;
	}

	//*_ transaction_id
	if(read_int(4, b + uti_transaction_id, b.end) != tracker.output_transaction_ids[TR_CONNECT])
		return;

	cout << "* Recv  :\t" << Csocket::inet_ntoa(tracker.host) << "\t" << (::time(NULL) % 100) << "\tSYN A\n";//DEB
	tracker.status = Cserver::ST_CONNECTED | Cserver::ST_PENDING;	//*_ open connection
	printStatus(tracker);//DEB
	//tracker.delay = false;

	//*_ connection_id
	long long recv_connection_id = read_int(8, b + uti_connection_id, b.end);
	tracker.connection_id = recv_connection_id;

	//*_ recv_time
	tracker.recv_time = ::time(NULL);

	//*_ Send HELLO
	send_summary(tracker, m_a);
}

/**
 *_ Take the appropriate action if a HELLO packet is received.
 */
void Ctransaction::process_hello(const_memory_range b, Cserver::t_tracker& tracker)
{
	//*_ connection_id
	long long recv_connection_id = read_int(8, b + uti_connection_id, b.end);
	if (recv_connection_id != tracker.connection_id)
		return;

	//*_ status
	if(tracker.status == Cserver::ST_DISCONNECTED ||
			tracker.status == Cserver::ST_PENDING)
		return;
	cout << "* Recv  :\t" << Csocket::inet_ntoa(tracker.host) << "\t" << (::time(NULL) % 100) << "\tHELLO\n";//DEB
	/*if(tracker.status == Cserver::ST_SYN)
	{
		tracker.status = Cserver::ST_CONNECTED;
		printStatus(tracker);//DEB
	}*/

	//*_ recv_time
	tracker.recv_time = ::time(NULL);
}

/**
 *_ Take the appropriate action if a SUMMARY packet is received.
 */
void Ctransaction::process_summary(const_memory_range b, Cserver::t_tracker& tracker)
{
	//*_ connection_id
	long long recv_connection_id = read_int(8, b + uti_connection_id, b.end);
	if (recv_connection_id != tracker.connection_id)
		return;

	//*_ transaction_id
	tracker.input_transaction_ids[TR_UNIFY] = read_int(4, b + uti_transaction_id, b.end);

	//*_ status
	if((tracker.status & (Cserver::ST_CONNECTED | Cserver::ST_SYN)) == 0)	//*_ drop if not connected or in SYN status
		return;
	cout << "* Recv  :\t" << Csocket::inet_ntoa(tracker.host) << "\t" << (::time(NULL) % 100) << "\tSUMMARY\n";//DEB
	if(tracker.status & Cserver::ST_SYN)
	{
		tracker.status = Cserver::ST_CONNECTED | Cserver::ST_SUMMARY;	//*_ open connection
		printStatus(tracker);//DEB
		//tracker.delay = false;
	}
	else
	{
		tracker.status |= Cserver::ST_SUMMARY;
		cout << "* Status:\t\t\t" << (::time(NULL) % 100) << "\t+ SUMMMARY\n";//DEB
		printStatus(tracker);//DEB
	}

	//*_ recv_time
	tracker.recv_time = ::time(NULL);

	//*_ action
	int summ_payload_size = b.size() - ut_summary_size;
	if(summ_payload_size % 21 != 0 && summ_payload_size != 1)
		return; //*_ Incorrect size
	if(summ_payload_size == 1)
	{
		if(read_int(1, b + ut_summary_size, b.end) & FL_SUMMARY_FILE_BOR)
		{
			if(!tracker.border_tracker)
				m_server.new_border_tracker(tracker);
		}
		cout << "*** border tracker from SUMMARY\n";
	}
	else
		m_server.unify_swarms(b.sub_range(ut_summary_size, summ_payload_size).string(), &tracker);
	m_server.build_updates();

	//*_ Send  UPDATE (SUMMARY flag)
	send_update(tracker.connection_id, tracker.input_transaction_ids[TR_UNIFY], m_a, tracker.update,
			FL_UPDATE_SUMMARY | (m_server.border_tracker() ? FL_UPDATE_BOR : 0));
}

/**
 *_ Take the appropriate action if an UPDATE packet is received.
 */
void Ctransaction::process_update(const_memory_range b, Cserver::t_tracker& tracker)
{
	//*_ connection_id
	long long recv_connection_id = read_int(8, b + uti_connection_id, b.end);
	if (recv_connection_id != tracker.connection_id)
		return;

	//*_ flags
	unsigned char flags = read_int(1, b + ut_update_flags, b.end);

	//*_ TODO: OPTIMIZATION probably needed here!
	//*_ transaction_id
	int recv_transaction_id = read_int(4, b + uti_transaction_id, b.end);
	if(flags & FL_UPDATE_SUMMARY && (flags & FL_UPDATE_ACK) == 0)	//*_ UPDATE S
	{
		if(recv_transaction_id != tracker.output_transaction_ids[TR_UNIFY])
			return;
	}
	else if(flags & FL_UPDATE_SUMMARY && flags & FL_UPDATE_ACK && tracker.status & Cserver::ST_SUMMARY) //*_ UPDATE SA
	{
		if(recv_transaction_id != tracker.input_transaction_ids[TR_UNIFY])
			return;
	}

	//*_ status
	if((tracker.status & Cserver::ST_CONNECTED) == 0)	//*_ drop if not connected
		return;

	//*_ recv_time
	tracker.recv_time = ::time(NULL);

	//*_ action
	//m_server.update(b.sub_range(ut_update_size, b.size() - ut_update_size).string(), &tracker);
	m_server.update(const_memory_range(b + ut_update_size, b.size() - ut_update_size), &tracker);

	//*_ flags
	cout << "* Recv  :\t" << Csocket::inet_ntoa(tracker.host) << "\t" << (::time(NULL) % 100) << "\tUPDATE " <<
			((flags & FL_UPDATE_SUMMARY) ? "S" : "") <<
			((flags & FL_UPDATE_ACK) ? "A" : "") <<
			((flags & FL_UPDATE_BOR) ? "B" : "") << endl;//DEB
	//*_ UPDATE S
	if(flags & FL_UPDATE_SUMMARY && (flags & FL_UPDATE_ACK) == 0)
	{
		tracker.status &= ~Cserver::ST_PENDING;	//*_ unset PENDING status flag
		cout << "* Status:\t\t\t" << (::time(NULL) % 100) << "\t- PENDING\n";//DEB
		printStatus(tracker);//DEB
		tracker.summary.clear();
		m_server.build_updates();
		//*_ Send UPDATE SA
		send_update(tracker.connection_id,
				tracker.output_transaction_ids[TR_UNIFY], m_a, tracker.update, FL_UPDATE_SUMMARY | FL_UPDATE_ACK);
	}
	//*_ UPDATE SA
	else if(flags & FL_UPDATE_SUMMARY && flags & FL_UPDATE_ACK && tracker.status & Cserver::ST_SUMMARY)
	{
		tracker.status &= ~Cserver::ST_SUMMARY;	//*_ unset SUMMARY status flag
		cout << "* Status:\t\t\t" << (::time(NULL) % 100) << "\t- SUMMARY\n";//DEB
		printStatus(tracker);//DEB
		// TODO: if(flags & (FL_UPDATE_SUMMARY | FL_UPDATE_ACK))
	}
	//*_ UPDATE A
	else if((flags & FL_UPDATE_SUMMARY) == 0 && flags & FL_UPDATE_ACK)
	{
		tracker.status &= ~Cserver::ST_UPDATING;//*_ unset UPDATING status flag
		cout << "* Status:\t\t\t" << (::time(NULL) % 100) << "\t- UPDATING\n";//DEB
		printStatus(tracker);//DEB
		//tracker.clean_up_sent_peers();
	}
	//*_ UPDATE (normal, no flags)
	else if((flags & (FL_UPDATE_SUMMARY | FL_UPDATE_ACK)) == 0)
	{
		//*_ Send empty UPDATE A
		send_update(tracker.connection_id, recv_transaction_id, m_a, "", FL_UPDATE_ACK);
	}
	else
		cout << "*\n";
	if(flags & FL_UPDATE_BOR)
	{
		if(!tracker.border_tracker)
			m_server.new_border_tracker(tracker);
	}
}

/**
 *_ Take the appropriate action if a SYN packet is received.
 */
void Ctransaction::process_candidature(const_memory_range b, Cserver::t_tracker& tracker)
{
	//*_ connection_id
	long long recv_connection_id = read_int(8, b + uti_connection_id, b.end);
	if (recv_connection_id != tracker.connection_id)
		return;

	//*_ transaction_id
	int recv_transaction_id = read_int(4, b + uti_transaction_id, b.end);

	//*_ status
	if(tracker.status == Cserver::ST_DISCONNECTED
			|| tracker.status == Cserver::ST_PENDING)
		return;		//*_ Drop it if not connected

	unsigned char flags = read_int(1, b + ut_candidature_flags, b.end);

	//*_ CANDIDATURE A
	if(flags & FL_CANDIDATURE_ACK)
	{
		//*_ transaction_id
		if(recv_transaction_id != tracker.output_transaction_ids[TR_CANDIDATURE])
			return;

		if(tracker.status & Cserver::ST_SEND_CANDIDATURE)
		{
			tracker.status &= ~Cserver::ST_SEND_CANDIDATURE;
			m_server.dec_n_send_candidature();
		}
	}
	//*_ CANDIDATURE normal (no flags)
	else
	{
		//*_ Send empty CANDIDATURE A
		send_candidature(tracker.connection_id, recv_transaction_id, m_a, m_server.mandates(), FL_CANDIDATURE_ACK);

		//*_ Update the tracker's number of mandates
		tracker.mandates = read_int(4, b + ut_candidature_size, b.end);

		if(!m_server.election_campaign())
			m_server.init_election_campaign(&tracker);
		else
		{
			if(tracker.status & Cserver::ST_RECV_CANDIDATURE)
			{
				tracker.status &= ~Cserver::ST_RECV_CANDIDATURE;
				m_server.dec_n_recv_candidature();
			}
		}
	}

	printStatus(tracker);//DEB

	//*_ If all CANDIDATURE packets have been changed finalize election campaign and choose the swarm leaders.
	if(m_server.check_election_campaign_termination())
	{
		m_server.choose_swarm_leaders();
	}

	cout << "* Recv  :\t" << Csocket::inet_ntoa(tracker.host) << "\t" << (::time(NULL) % 100) << "\tCANDIDATURE "
		<< ((flags & FL_CANDIDATURE_ACK) ? "A" : "") << endl;//DEB
	//*_ recv_time
	tracker.recv_time = ::time(NULL);

}

/**
 *_ Take the appropriate action if a LEADER packet is received.
 */
void Ctransaction::process_leader(const_memory_range b, Cserver::t_tracker& tracker)
{
	//*_ connection_id
	long long recv_connection_id = read_int(8, b + uti_connection_id, b.end);
	if (recv_connection_id != tracker.connection_id)
		return;

	//*_ transaction_id
	int recv_transaction_id = read_int(4, b + uti_transaction_id, b.end);

	//*_ status
	if(tracker.status == Cserver::ST_DISCONNECTED ||
			tracker.status == Cserver::ST_PENDING)
		return;		//*_ Drop it if not connected
	unsigned char flags = read_int(1, b + ut_candidature_flags, b.end);

	//*_ CANDIDATURE A
	if(flags & FL_LEADER_ACK)
	{
		//*_ transaction_id
		if(recv_transaction_id != tracker.output_transaction_ids[TR_LEADER])
			return;

		tracker.status &= ~Cserver::ST_SEND_LEADER;
		tracker.leader.clear();
	}
	//*_ CANDIDATURE normal (no flags)
	else
	{
		//*_ Send empty LEADER A
		send_leader(tracker.connection_id, recv_transaction_id, m_a, "", FL_LEADER_ACK);

		//*_ Update the swarm leader for the tracker
		string payload = string(reinterpret_cast<const char*>(b + ut_leader_size), b.size() - ut_leader_size);
		if(payload.size() % 20 == 0)
		{
			for(int k = 0; k < payload.size(); k += 20)
				m_server.set_swarm_leader(payload.substr(k, 20), tracker);
		}
	}

	cout << "* Recv  :\t" << Csocket::inet_ntoa(tracker.host) << "\t" << (::time(NULL) % 100) << "\tLEADER "
		<< ((flags & FL_LEADER_ACK) ? "A" : "") << endl;//DEB
	//*_ recv_time
	tracker.recv_time = ::time(NULL);
}

/**
 *_ Writes in the output the bytes for the common part of the header of every TSUP packet.
 */
void Ctransaction::make_header(char *output, long long connection_id, int transaction_id, int action)
{
	//*_ Connection identifier -- can identify if a tracker restarted and resolves security issues.
	write_int(8, output + uti_connection_id, connection_id);
	//*_ Packet "type".
	write_int(4, output + uti_action, action);
	//*_ Transaction ID.
	write_int(4, output + uti_transaction_id, transaction_id);
	//*_ Port (useful for tracker identification).
	write_int(2, output + ut_port, m_server.tsup_port());
}

/**
 *_ Sends a SYN packet to another tracker in order to establish a virtual connection with it.
 */
void Ctransaction::send_syn(long long connection_id, int transaction_id, const sockaddr_in &a, unsigned flags)
{
	if(flags & FL_SYN_ACK)
		cout << "* Send  :\t" << Csocket::inet_ntoa(a.sin_addr.s_addr) << "\t" << (::time(NULL) % 100) << "\tSYN A\n";//DEB
	else
		cout << "* Send  :\t" << Csocket::inet_ntoa(a.sin_addr.s_addr) << "\t" << (::time(NULL) % 100) << "\tSYN\n";//DEB
	const int cb_d = 2 << 10;
	char d[cb_d];

	m_server.reset_hello_time();

	make_header(d, connection_id, transaction_id, uta_syn);
	write_int(1, d + ut_syn_flags, flags);

	send(const_memory_range(d, ut_syn_size), a);
}

/**
 *_ Sends a HELLO packet to another tracker in order to keep alive the virtual connection with it.
 */
void Ctransaction::send_hello(long long connection_id, const sockaddr_in &a)
{
	cout << "* Send  :\t" << Csocket::inet_ntoa(a.sin_addr.s_addr) << "\t" << (::time(NULL) % 100) << "\tHELLO\n";//DEB
	const int cb_d = 2 << 10;
	char d[cb_d];

	m_server.reset_hello_time();

	make_header(d, connection_id, 0, uta_hello);
	send(const_memory_range(d, ut_hello_size), a);
}

/**
 *_ Sends a SUMMARY packet to another tracker in order to inform him which are my info_hashes.
 */
void Ctransaction::send_summary(long long connection_id, int transaction_id, const sockaddr_in &a, std::string payload)
{
	cout << "* Send  :\t" << Csocket::inet_ntoa(a.sin_addr.s_addr) << "\t" << (::time(NULL) % 100) << "\tSUMMARY\n";//DEB
	char *d = new char[ut_summary_size + payload.size()];

	m_server.reset_hello_time();

	//*_ header
	make_header(d, connection_id, transaction_id, uta_summary);

	//*_ payload
	memcpy(d + ut_summary_size, payload.data(), payload.size());

	send(const_memory_range(d, ut_summary_size + payload.size()), a);
}

/**
 *_ Sends a SUMMARY packet to another tracker in order to inform him which are my info_hashes.
 */
void Ctransaction::send_summary(Cserver::t_tracker& tracker, const sockaddr_in &a)
{
	string payload = m_server.get_info_hashes();
	tracker.output_transaction_ids[TR_UNIFY] = rand();
	send_summary(tracker.connection_id, tracker.output_transaction_ids[TR_UNIFY], a, payload);
	tracker.summary += payload;
}

/**
 *_ Sends an UPDATE packet to another tracker in order to inform him which are the new peers for some swarms or which peers died.
 */
void Ctransaction::send_update(long long connection_id, int transaction_id, const sockaddr_in &a, std::string payload, unsigned char flags)
{
	cout << "* Send  :\t" << Csocket::inet_ntoa(a.sin_addr.s_addr) << "\t" << (::time(NULL) % 100) << "\tUPDATE " <<
			((flags & FL_UPDATE_SUMMARY) ? "S" : "") <<
			((flags & FL_UPDATE_ACK) ? "A" : "") << endl;//DEB
	char *d = new char[ut_update_size + payload.size()];

	m_server.reset_hello_time();

	//*_ header
	make_header(d, connection_id, transaction_id, uta_update);
	write_int(1, d + ut_update_flags, flags);

	//*_ payload
	memcpy(d + ut_update_size, payload.data(), payload.size());

	send(const_memory_range(d, ut_update_size + payload.size()), a);
}

/**
 *_ Sends a CANDIDATURE packet to another tracker in order to inform him how many mandates do I have.
 */
void Ctransaction::send_candidature(long long connection_id, int transaction_id, const sockaddr_in &a, int mandates, unsigned char flags)
{
	cout << "* Send  :\t" << Csocket::inet_ntoa(a.sin_addr.s_addr) << "\t" << (::time(NULL) % 100) << "\tCANDIDATURE " <<
			((flags & FL_CANDIDATURE_ACK) ? "A" : "") << endl;//DEB
	const int size = ut_candidature_size + ((flags & FL_CANDIDATURE_ACK) ? 0 : 4);
	char *d = new char[size];

	m_server.reset_hello_time();

	//*_ header
	make_header(d, connection_id, transaction_id, uta_candidature);
	write_int(1, d + ut_candidature_flags, flags);

	//*_ payload
	if((flags & FL_CANDIDATURE_ACK) == 0)
		write_int(4, d + ut_candidature_size, mandates);

	send(const_memory_range(d, size), a);
}

/**
 *_ Sends a LEADER packet to another tracker in order to inform him who is the leader in the swarms from 'payload'.
 */
void Ctransaction::send_leader(long long connection_id, int transaction_id, const sockaddr_in &a, std::string payload, unsigned char flags)
{
	if((flags & FL_LEADER_ACK) == 0 && payload.size() % 20 != 0)
		return;

	cout << "* Send  :\t" << Csocket::inet_ntoa(a.sin_addr.s_addr) << "\t" << (::time(NULL) % 100) << "\tLEADER " <<
			((flags & FL_LEADER_ACK) ? "A" : "") << endl;//DEB
	const int size = ut_leader_size + ((flags & FL_LEADER_ACK) ? 0 : 20);
	char *d = new char[size];

	m_server.reset_hello_time();

	//*_ header
	make_header(d, connection_id, transaction_id, uta_leader);
	write_int(1, d + ut_leader_flags, flags);

	//*_ payload
	if((flags & FL_LEADER_ACK) == 0)
		memcpy(d + ut_leader_size, payload.data(), payload.size());

	send(const_memory_range(d, size), a);
}
