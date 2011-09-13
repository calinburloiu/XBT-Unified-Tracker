#include "stdafx.h"
#include "server.h"

#include <boost/foreach.hpp>
#include <boost/format.hpp>
#include <sql/sql_query.h>
#include <iostream>
#include <sstream>
#include <signal.h>
#include <bt_misc.h>
#include <bt_strings.h>
#include <stream_int.h>
#include "transaction.h"

//DEB
void printStatus(Cserver::t_tracker &tracker)
{
	cout << "* Status:\t" << Csocket::inet_ntoa(tracker.host) << "\t" << (::time(NULL) % 100) << "\t"
		<< ((tracker.status & Cserver::ST_CONNECTED) ? "CONNECTED " : "")
		<< ((tracker.status & Cserver::ST_PENDING) ? "PENDING " : "")
		<< ((tracker.status & Cserver::ST_SYN) ? "SYN " : "")
		<< ((tracker.status & Cserver::ST_SUMMARY) ? "SUMMARY " : "")
		<< ((tracker.status & Cserver::ST_UPDATING) ? "UPDATING " : "")
		<< ((tracker.status & Cserver::ST_SEND_CANDIDATURE) ? "SEND_CANDIDATURE " : "")
		<< ((tracker.status & Cserver::ST_RECV_CANDIDATURE) ? "RECV_CANDIDATURE " : "")
		<< ((tracker.status & Cserver::ST_SEND_LEADER) ? "SEND_LEADER " : "")
		<< endl;//DEB
}

//DEB
void printStrHex(string str)
{
	const char *buf = str.data();
	unsigned char c;
	for(int i=0; i<str.size(); i++)
	{
		c = (unsigned char)buf[i];
		cout << hex << (unsigned int)c << ",";
	}
	cout << dec << endl;
}

static volatile bool g_sig_term = false;

Cserver::Cserver(Cdatabase& database, const std::string& table_prefix, bool use_sql, const std::string& conf_file):
	m_database(database)
{
	m_fid_end = 0;

	for (int i = 0; i < 8; i++)
		m_secret = m_secret << 8 ^ rand();
	m_conf_file = conf_file;
	m_table_prefix = table_prefix;
	m_time = ::time(NULL);
	m_use_sql = use_sql;
	m_transaction = NULL; //*_
	m_tsup_socket = NULL; //*_
	m_election_campaign = false;
	m_mandates = 0;
	m_internal = false;
	m_external = false;
}

Cserver::t_tracker::t_tracker()
{
	tid = -1;
	memset(name, 0, 256);
	host = INADDR_NONE;
	port = -1;
	nat_port = -1;
	//memset(version, 0, 64);
	memset(description, 0, 256);

	status = ST_DISCONNECTED | ST_PENDING;
	border_tracker = false;
	recv_time = reconnect_time = ::time(NULL);
	retry_times = 5;
	connection_id = NO_ID;
	nat = false;
	external = false;
	n_sent_dead_peers = 0;
	mandates = INT_MAX;
}

/**
 *_ Acknowledged peers from the last update are erased if are dead.
 */
void Cserver::t_tracker::clean_up_sent_peers()
{
	for(int i=0; i < n_sent_dead_peers; i++)
	{
		cout << "*** clean_up_sent_peers: dead\n";//DEB
		if(sent_dead_peers[i]->second.file == NULL)
			cout << "file is NULL\n";
		sent_dead_peers[i]->second.file->peers.erase(sent_dead_peers[i]->first);
	}

	n_sent_dead_peers = 0;
}

/**
 *_ Check TSUP timers and if some of them expired take the appropriate actions.
 */
void Cserver::tsup_timers()
{
	struct sockaddr_in sa = {0};
	bool b_update_timeout;
	bool b_hello_timeout;
	bool updates_builded = false;

	//*_ On update timeout build the updates and mark this event
	if(time() - m_update_time > m_config.m_update_interval)
	{
		b_update_timeout = true;
		cout << "* (update timeout:)\t" << (::time(NULL) % 100) << "\n";//DEB
		m_update_time = ::time(NULL); //*_ Reset update timer

		build_updates();
		updates_builded = true;
	}
	else
		b_update_timeout = false;

	//*_ On hello timeout
	if(time() - m_hello_time > m_config.m_hello_interval)
	{
		b_hello_timeout = true;
		cout << "* (hello timeout:)\t" << (::time(NULL) % 100) << "\n";//DEB

		//*_ Update hello timer
		//m_hello_time = ::time(NULL);
	}
	else
		b_hello_timeout = false;

	//*_ On mandate timeout
	if(time() - m_mandate_time > m_config.m_mandate_interval)
	{
		init_election_campaign(NULL);
	}

	//*_ Check TSUP timers and take the appropiate actions for those who expired
	if(b_hello_timeout || b_update_timeout)
	{
		t_tracker *tracker;
		for(map<tracker_key,t_tracker>::iterator it = m_trackers.begin(); it != m_trackers.end(); it++)
		{
			tracker = &it->second;

			if(tracker->delay) cout << "delay " << Csocket::inet_ntoa(tracker->host) << endl;//DEB

			//*_ Close the virtual connection with trackers that didn't send anything in the last disconnect_interval seconds.
			if(time() - tracker->recv_time > m_config.m_disconnect_interval)
			{
				if(tracker->status != ST_PENDING && tracker->status != ST_DISCONNECTED)
				{
					tracker->status = ST_DISCONNECTED | ST_PENDING;
					cout << "* (recv timeout:)\n";
					printStatus(*tracker);//DEB
					tracker->retry_times = m_config.m_retry_times;
					//tracker->delay = generate_delay();
				}
			}

			if(!tracker->nat)
				Csocket::make_sockaddr_in(sa, tracker->host, tracker->port);
			else if(tracker->nat_port > -1)
				Csocket::make_sockaddr_in(sa, tracker->host, tracker->nat_port);
			else
				continue;

			if(tracker->status & ST_CONNECTED)
			{
				if(b_hello_timeout)
				{
					if(tracker->status & ST_PENDING)
					{
						//*_ Send SUMMARY
						//tracker->output_transaction_ids[TR_UNIFY] = rand();
						m_transaction->send_summary(tracker->connection_id,
								tracker->output_transaction_ids[TR_UNIFY], sa, tracker->summary);
					}
					else if(tracker->status & ST_SUMMARY)
					{
						if(b_update_timeout && !updates_builded)
						{
							build_updates();
							updates_builded = true;
						}
						//*_ Send UPDATE S
						m_transaction->send_update(tracker->connection_id,
								tracker->input_transaction_ids[TR_UNIFY], sa, tracker->update, FL_UPDATE_SUMMARY);
					}
					else if(tracker->status & ST_SEND_CANDIDATURE)
					{
						//*_ Send CANDIDATURE
						tracker->output_transaction_ids[TR_CANDIDATURE] = rand();
						m_transaction->send_candidature(tracker->connection_id,
								tracker->output_transaction_ids[TR_CANDIDATURE], sa, m_mandates, 0);
					}
					else if(tracker->status & ST_SEND_LEADER)
					{
						//*_ Send LEADER
						tracker->output_transaction_ids[TR_LEADER] = rand();
						m_transaction->send_leader(tracker->connection_id,
								tracker->output_transaction_ids[TR_LEADER], sa, tracker->leader, 0);
					}

					if((tracker->status
							& (ST_PENDING | ST_SUMMARY | ST_UPDATING | ST_SEND_CANDIDATURE | ST_SEND_LEADER)) == 0)
						//*_ Send HELLO
						m_transaction->send_hello(tracker->connection_id, sa);
				}

				if ( (tracker->status & (ST_PENDING | ST_SUMMARY)) == 0
						&& (b_update_timeout && !tracker->update.empty() || b_hello_timeout && tracker->status & ST_UPDATING)
						|| b_update_timeout && !b_hello_timeout && (tracker->status & ST_PENDING) == 0 && !tracker->update.empty())
				{
					//*_ Send UPDATE
					m_transaction->send_update(tracker->connection_id,
							tracker->output_transaction_ids[TR_UPDATE], sa, tracker->update, FL_UPDATE_NORMAL);
					tracker->status |= ST_UPDATING;
					printStatus(*tracker);//DEB
				}
			}
			else if(b_hello_timeout)
			{
				if(tracker->status == ST_PENDING)
				{
					if(!tracker->delay)
					{
						//*_ Send SYN
						tracker->output_transaction_ids[TR_CONNECT] = rand();
						m_transaction->send_syn(tracker->connection_id, tracker->output_transaction_ids[TR_CONNECT], sa, 0);
						tracker->retry_times--;
						if (tracker->retry_times <= 0)
						{
							tracker->reconnect_time = ::time(NULL);
							tracker->retry_times = m_config.m_retry_times;
							tracker->status = ST_DISCONNECTED;
							cout << "* (retry_times == 0:)\n";
							printStatus(*tracker);//DEB
						}
					}
					else
						tracker->delay = false;
				}
				else if(tracker->status == ST_DISCONNECTED && time() - tracker->reconnect_time > m_config.m_reconnect_interval)
				{
					cout << "* (reconnect timeout:)\t" << (::time(NULL) % 100) << "\n";//DEB
					if(!tracker->delay)
					{
						//*_ Send SYN
						tracker->output_transaction_ids[TR_CONNECT] = rand();
						m_transaction->send_syn(tracker->connection_id, tracker->output_transaction_ids[TR_CONNECT], sa, 0);
						tracker->reconnect_time = ::time(NULL);
					}
					else
						tracker->delay = false;
				}
				else if(tracker->status == ST_SYN)
				{
					//*_ Send SYN_ACK
					m_transaction->send_syn(tracker->connection_id, tracker->input_transaction_ids[TR_CONNECT], sa, FL_SYN_ACK);
				}
			}//else if(b_hello_timeout)
		}// for each tracker
	}
}

/**
 * Start the server (main loop).
 */
int Cserver::run()
{
	// ** Read the configuration from the DB (*_config table) and from the config file
	read_config();
	cout << "hello = " << m_config.m_hello_interval <<
			"\nreconnect = " << m_config.m_reconnect_interval <<
			"\ndisconnect = " << m_config.m_disconnect_interval <<
			"\nmax_delay = " << m_config.m_max_delay_interval <<
			"\nupdate = " << m_config.m_update_interval <<
			"\nretry_times = " << m_config.m_retry_times <<
			"\nip = " << m_config.m_ip <<
			"\ntracker_name = " << m_config.m_tracker_name <<
			"\nmandate_interval = " << m_config.m_mandate_interval << endl << endl;//DEB

	// ** Verify the DB and its integrity
	if (test_sql())
		return 1;
	// ** Create the epoll object
	if (m_epoll.create(1 << 10) == -1)
	{
		std::cerr << "epoll_create failed" << std::endl;
		return 1;
	}

	// ** Sockets for listening (TCP & UDP)
	t_tcp_sockets lt;
	t_udp_sockets lu;

	// ** Binding and listening
	BOOST_FOREACH(Cconfig::t_listen_ipas::const_reference j, m_config.m_listen_ipas)
	{
		// ** TCP
		BOOST_FOREACH(Cconfig::t_listen_ports::const_reference i, m_config.m_listen_ports)
		{
			Csocket l;
			if (l.open(SOCK_STREAM) == INVALID_SOCKET)
				std::cerr << "socket failed: " << Csocket::error2a(WSAGetLastError()) << std::endl;
			else if (l.setsockopt(SOL_SOCKET, SO_REUSEADDR, true),
				l.bind(j, htons(i)) )
				std::cerr << "bind failed (TCP): " << Csocket::error2a(WSAGetLastError()) << std::endl;
			else if (l.listen())
				std::cerr << "listen failed: " << Csocket::error2a(WSAGetLastError()) << std::endl;
			else
			{
#ifdef SO_ACCEPTFILTER
				accept_filter_arg afa;
				bzero(&afa, sizeof(afa));
				strcpy(afa.af_name, "httpready");
				if (l.setsockopt(SOL_SOCKET, SO_ACCEPTFILTER, &afa, sizeof(afa)))
					std::cerr << "setsockopt failed: " << Csocket::error2a(WSAGetLastError()) << std::endl;
#elif TCP_DEFER_ACCEPT
				if (l.setsockopt(IPPROTO_TCP, TCP_DEFER_ACCEPT, true))
					std::cerr << "setsockopt failed: " << Csocket::error2a(WSAGetLastError()) << std::endl;
#endif
				lt.push_back(Ctcp_listen_socket(this, l));
				if (!m_epoll.ctl(EPOLL_CTL_ADD, l, EPOLLIN | EPOLLOUT | EPOLLPRI | EPOLLERR | EPOLLHUP, &lt.back()))
					continue;
			}
			return 1;
		}
		// ** UDP
		BOOST_FOREACH(Cconfig::t_listen_ports::const_reference i, m_config.m_listen_ports)
		{
			Csocket l;
			if (l.open(SOCK_DGRAM) == INVALID_SOCKET)
				std::cerr << "socket failed: " << Csocket::error2a(WSAGetLastError()) << std::endl;
			else if (l.setsockopt(SOL_SOCKET, SO_REUSEADDR, true),
				l.bind(j, htons(i)))
				std::cerr << "bind failed (UDP): " << Csocket::error2a(WSAGetLastError()) << std::endl;
			else
			{
				if(m_tsup_socket == NULL)
					m_tsup_socket = new Csocket(static_cast<SOCKET>(l));
				lu.push_back(Cudp_listen_socket(this, l));
				if (!m_epoll.ctl(EPOLL_CTL_ADD, l, EPOLLIN | EPOLLPRI | EPOLLERR | EPOLLHUP, &lu.back()))
					continue;
			}
			return 1;
		}
	}

	//*_ TSUP listening port
	m_tsup_port = *m_config.m_listen_ports.begin();

	// ** Clean-up the peers
	clean_up();
	// ** Synchronize with DB
	read_db_deny_from_hosts();
	read_db_files();
	read_db_users();
	read_db_trackers();	//*_
	write_db_files();
	write_db_users();

	//*_ Initialize TSUP timers
	m_hello_time = ::time(NULL) - m_config.m_hello_interval - 1;
	m_mandate_time = ::time(NULL) - 840;// TODO: Correct initial m_mandate_tiem
	m_update_time = ::time(NULL);

	//DEB
	// files
	for(t_files::iterator iter = m_files.begin(); iter != m_files.end(); iter++)
	{
		cout << iter->second.fid << ": ";
		printStrHex(iter->first);;
	}

	//*_ Create a transaction object used for communicating packets to other trackers.
	// The communication is triggered by internal events (timers)
	m_transaction = new Ctransaction(*this, *m_tsup_socket);

	// ** Daemonize
#ifndef WIN32
	if (m_config.m_daemon)
	{
#if 1
		if (daemon(true, false))
			std::cerr << "daemon failed" << std::endl;
#else
		switch (fork())
		{
		case -1:
			std::cerr << "fork failed" << std::endl;
			break;
		case 0:
			break;
		default:
			exit(0);
		}
		if (setsid() == -1)
			std::cerr << "setsid failed" << std::endl;
#endif
		std::ofstream(m_config.m_pid_file.c_str()) << getpid() << std::endl;
		struct sigaction act;
		act.sa_handler = sig_handler;
		sigemptyset(&act.sa_mask);
		act.sa_flags = 0;
		if (sigaction(SIGTERM, &act, NULL))
			std::cerr << "sigaction failed" << std::endl;
		act.sa_handler = SIG_IGN;
		if (sigaction(SIGPIPE, &act, NULL))
			std::cerr << "sigaction failed" << std::endl;
	}
#endif
#ifdef EPOLL
	cout << "* EPOLL\n";// TODO: make EPOLL work on my system
	const int c_events = 64;

	epoll_event events[c_events];
#else
	fd_set fd_read_set;
	fd_set fd_write_set;
	fd_set fd_except_set;
#endif

	// ** Accept connections (epoll or select)
	int r, prev_time;
	while (!g_sig_term)
	{
#ifdef EPOLL
		r = m_epoll.wait(events, c_events, 5000);
		if (r == -1)
			std::cerr << "epoll_wait failed: " << errno << std::endl;
		else
		{
			prev_time = m_time;
			m_time = ::time(NULL);
			for (int i = 0; i < r; i++)
				reinterpret_cast<Cclient*>(events[i].data.ptr)->process_events(events[i].events);
			if (m_time == prev_time)
				continue;
			for (t_connections::iterator i = m_connections.begin(); i != m_connections.end(); )
			{
				if (i->run())
					i = m_connections.erase(i);
				else
					i++;
			}
		}
#else
		FD_ZERO(&fd_read_set);
		FD_ZERO(&fd_write_set);
		FD_ZERO(&fd_except_set);
		int n = 0;
		BOOST_FOREACH(t_connections::reference i, m_connections)
		{
			int z = i.pre_select(&fd_read_set, &fd_write_set);
			n = std::max(n, z);
		}
		BOOST_FOREACH(t_tcp_sockets::reference i, lt)
		{
			FD_SET(i.s(), &fd_read_set);
			n = std::max<int>(n, i.s());
		}
		BOOST_FOREACH(t_udp_sockets::reference i, lu)
		{
			FD_SET(i.s(), &fd_read_set);
			n = std::max<int>(n, i.s());
		}
		timeval tv;
		tv.tv_sec = 5;
		tv.tv_usec = 0;
		if (select(n + 1, &fd_read_set, &fd_write_set, &fd_except_set, &tv) == SOCKET_ERROR)
			std::cerr << "select failed: " << Csocket::error2a(WSAGetLastError()) << std::endl;
		else
		{
			m_time = ::time(NULL);
			BOOST_FOREACH(t_tcp_sockets::reference i, lt)
			{
				if (FD_ISSET(i.s(), &fd_read_set))
					accept(i.s());
			}
			BOOST_FOREACH(t_udp_sockets::reference i, lu)
			{
				if (FD_ISSET(i.s(), &fd_read_set))
					Ctransaction(*this, i.s()).recv();
			}
			for (t_connections::iterator i = m_connections.begin(); i != m_connections.end(); )
			{
				if (i->post_select(&fd_read_set, &fd_write_set))
					i = m_connections.erase(i);
				else
					i++;
			}
		}
#endif

		// ** Synchronize DB tables if their corresponding timeout expired
		if (time() - m_read_config_time > m_config.m_read_config_interval)
			read_config();
		else if (time() - m_clean_up_time > m_config.m_clean_up_interval)
			clean_up();
		else if (time() - m_read_db_deny_from_hosts_time > m_config.m_read_db_interval)
			read_db_deny_from_hosts();
		else if (time() - m_read_db_files_time > m_config.m_read_db_interval)
			read_db_files();
		else if (time() - m_read_db_users_time > m_config.m_read_db_interval)
			read_db_users();
		else if (m_config.m_write_db_interval && time() - m_write_db_files_time > m_config.m_write_db_interval)
			write_db_files();
		else if (m_config.m_write_db_interval && time() - m_write_db_users_time > m_config.m_write_db_interval)
			write_db_users();

		//*_ Check TSUP timers
		tsup_timers();
	}

	// ** Save changes before exit
	write_db_files();
	write_db_users();
	unlink(m_config.m_pid_file.c_str());
	return 0;
}

void Cserver::accept(const Csocket& l)
{
	sockaddr_in a;
	while (1)
	{
		socklen_t cb_a = sizeof(sockaddr_in);
		Csocket s = ::accept(l, reinterpret_cast<sockaddr*>(&a), &cb_a);
		if (s == SOCKET_ERROR)
		{
			if (WSAGetLastError() == WSAECONNABORTED)
				continue;
			if (WSAGetLastError() != WSAEWOULDBLOCK)
				std::cerr << "accept failed: " << Csocket::error2a(WSAGetLastError()) << std::endl;
			break;
		}
		t_deny_from_hosts::const_iterator i = m_deny_from_hosts.lower_bound(ntohl(a.sin_addr.s_addr));
		if (i != m_deny_from_hosts.end() && ntohl(a.sin_addr.s_addr) >= i->second.begin)
		{
			m_stats.rejected_tcp++;
			continue;
		}
		m_stats.accepted_tcp++;
		if (s.blocking(false))
			std::cerr << "ioctlsocket failed: " << Csocket::error2a(WSAGetLastError()) << std::endl;
		std::auto_ptr<Cconnection> connection(new Cconnection(this, s, a));
		connection->process_events(EPOLLIN);
		if (connection->s() != INVALID_SOCKET)
		{
			m_connections.push_back(connection.release());
			m_epoll.ctl(EPOLL_CTL_ADD, m_connections.back().s(), EPOLLIN | EPOLLOUT | EPOLLPRI | EPOLLERR | EPOLLHUP | EPOLLET, &m_connections.back());
		}
	}
}

/**
 *_ Send a SUMMARY packet to each other tracker to announce a new torrent file.
 */
void Cserver::report_new_file(std::string info_hash)
{
	//*_ In a new swarm I am alone and I have leader mandate.
	//m_mandates++;

	if(m_trackers.empty()) return;
	cout << "*** report_new_file\n";//DEB

	sockaddr_in sa;
	t_tracker *tracker;
	string payload;

	//*_ Create the file payload.
	payload.reserve(21);
	payload += char(FL_SUMMARY_FILE_POS);
	payload += info_hash;

	BOOST_FOREACH(t_trackers::reference i, m_trackers)
	{
		tracker = &i.second;
		Csocket::make_sockaddr_in(sa, tracker->host, tracker->port);
		tracker->summary += payload;
		tracker->output_transaction_ids[TR_UNIFY] = rand();
		m_transaction->send_summary(tracker->connection_id, tracker->output_transaction_ids[TR_UNIFY], sa, tracker->summary);
		//*_ Activate PENDING flag in the tracker status.
		tracker->status |= ST_PENDING;
		printStatus(*tracker);//DEB
	}
}

/**
 *_ Send a SUMMARY packet to each other tracker to announce that a torrent file has been deleted.
 */
void Cserver::report_delete_file(std::string info_hash)
{
	if(m_trackers.empty()) return;
	cout << "*** report_delete_file\n";//DEB

	sockaddr_in sa;
	t_tracker *tracker;
	string payload;

	//*_ Create the file payload.
	payload.reserve(21);
	payload += char(FL_SUMMARY_FILE_NEG);
	payload += info_hash;

	//*_ If I am the swarm leader, the swarm remains without a leader.
	t_files::iterator it = m_files.find(info_hash);
	if(it != m_files.end())
	{
		if(it->second.swarm_leader == NULL)
			it->second.b_swarm_leader = false;
		if(it->second.swarm_leader_ext == NULL)
			it->second.b_swarm_leader_ext = false;
	}

	BOOST_FOREACH(t_trackers::reference i, m_trackers)
	{
		tracker = &i.second;
		Csocket::make_sockaddr_in(sa, tracker->host, tracker->port);
		tracker->summary += payload;
		tracker->output_transaction_ids[TR_UNIFY] = rand();
		m_transaction->send_summary(tracker->connection_id, tracker->output_transaction_ids[TR_UNIFY], sa, tracker->summary);
		//*_ Activate PENDING flag in the tracker status.
		tracker->status |= ST_PENDING;
		printStatus(*tracker);//DEB
	}
}

/**
 *_ Returns a payload for a SUMMARY packet which includes all the torrent info_hashes.
 */
std::string Cserver::get_info_hashes() const
{
	string payload;

	if(border_tracker())
		payload += char(FL_SUMMARY_FILE_BOR);
	else
	{
		payload.reserve(m_files.size() * 21);

		BOOST_FOREACH(t_files::const_reference i, m_files)
		{
			string file_payload;
			file_payload.reserve(21);
			file_payload += char(FL_SUMMARY_FILE_POS);
			file_payload += i.first;
			payload.append(file_payload);
		}
	}

	return payload;
}

/**
 *_ Adds 'tracker' into the swarm with 'info_hash' if it exists.
 */
void Cserver::unify_swarm(std::string info_hash, t_tracker *tracker)
{
	t_files::iterator it;

	it = m_files.find(info_hash);
	if(it != m_files.end())
	{
		t_file& file = it->second;

		//*_ Insert in the swarm the new unified tracker.
		file.new_arrivals = file.trackers.insert(tracker).second;

		//*_ Is the tracker a new arrival in the swarm?
		if(file.new_arrivals)
		{
			//*_ If it is the election campaign, send CANDIDATURE to the new tracker.
			if(m_election_campaign)
				tracker->status |= ST_SEND_CANDIDATURE;

			//*_ If there is a swarm leader report it to the new member
			if( (tracker->external ? (file.b_swarm_leader_ext && file.swarm_leader_ext == NULL)
					: (file.b_swarm_leader && file.swarm_leader == NULL)) )
			{
				tracker->leader += info_hash;
				tracker->status |= ST_SEND_LEADER;
			}
		}

		//DEB
		if(file.new_arrivals)
		{
			cout << "*** Unification:\n";
			cout << file.fid << ": ";
			printStrHex(info_hash);
			for(set<t_tracker *>::iterator j = file.trackers.begin(); j != file.trackers.end(); j++)
			{
				cout << "- " << (*j)->name << endl;

			}
		}
	}

	//*_ If this tracker is a border tracker, unify it with everybody.
	if(border_tracker())
	{
		// ** Access/add a file.
		t_file& file = m_files[info_hash];
		// ** If a new file was added, initialize the creation time.
		if (!file.ctime)
			file.ctime = time();
	}

}

/**
 *_ Processes the info_hashes received from a SUMMARY packet by adding 'tracker' to the common swarms.
 */
void Cserver::unify_swarms(std::string info_hashes, t_tracker *tracker)
{
	t_files::iterator it;

	for(int i = 0; i < info_hashes.size(); i += 21)
	{
		//*_ Negative (delete) summary
		if(info_hashes[i] & FL_SUMMARY_FILE_NEG)
		{
			it = m_files.find(info_hashes.substr(i + 1, 20));
			if(it != m_files.end())
			{
				t_file& file = it->second;
				file.trackers.erase(file.trackers.find(tracker));

				if(file.swarm_leader == tracker)
				{
					file.swarm_leader = NULL;
					file.b_swarm_leader = false;
				}
				if(file.swarm_leader_ext == tracker)
				{
					file.swarm_leader_ext = NULL;
					file.b_swarm_leader_ext = false;
				}
			}
		}
		//*_ Positive summary
		else
		{
			unify_swarm(info_hashes.substr(i + 1, 20), tracker);
		}
	}

/*	if(!m_anticipated_elections.empty())
		init_election_campaign(NULL);*/
}

/**
 *_ Updates the swarms with the information from payload 'updates' received from 'tracker'.
 */
void Cserver::update(const_memory_range update, t_tracker *tracker)
{
	//DEB
	cout << "Recv update: ";
	if(update.empty())
		cout << "(empty)\n";
	else
		printStrHex(update.string());

	string info_hash;
	int n_peers;
	unsigned char flags;
	in_addr_t host;
	in_port_t port;
	t_files::iterator itFiles;
	t_peers::iterator itPeers;

	 try {
	while(!update.empty())
	{
		//*_ Swarm header
		info_hash.assign(reinterpret_cast<const char*>(update + 0), 20);
		update += 20;
		n_peers = read_int(1, update, update.end) & 63;
		update++;

		itFiles = m_files.find(info_hash);
		//*_ The swarm doesn't exist, skip it.
		if(itFiles == m_files.end())
			update += n_peers * UPDATE_PEER_SIZE;

		//*_ Unify with the swarm in case there is no unification yet
		unify_swarm(info_hash, tracker);
/*		if(!m_anticipated_elections.empty())
			init_election_campaign(NULL);*/

		//*_ Peers
		for(int i = 0; i < n_peers; i++)
		{
			flags = read_int(1, update, update.end);
			update++;
			host = htonl(read_int(4, update, update.end));
			update += 4;
			port = htons(read_int(2, update, update.end));
			update += 2;

			peer_key_c peer_key(host, 0);

			//*_ negative update (deletes peers)
			if(flags & FL_UPDATE_PEER_NEG)
			{
				itPeers = itFiles->second.peers.find(peer_key);
				if(itPeers != itFiles->second.peers.end())
					itPeers->second.dead = true;
			}
			//*_ positive update (adds peers)
			else
			{
				t_peer& peer = itFiles->second.peers[peer_key];
				//*_ New peer
				if(peer.mtime == 0)
				{
					peer.downloaded = 0;
					peer.uploaded = 0;;
					peer.uid = 0;
					peer.port = port;
					peer.left = true;
					peer.origin = tracker->external ? PO_EXTERNAL : PO_INTERNAL;
					peer.tracker = tracker;
					//peer.peer_id;
				}
				peer.dead = false;
				peer.mtime = ::time(NULL);
				peer.file = &itFiles->second;
			}//positive update
		}//for each peer
	}//while reading updates
	 } catch(out_of_range_exception& e) {
	 	cout << e.what() << endl;//DEB
	 }
}

/**
 *_ Appends to the update string 'd' the information for a peer 'candidate' and deletes it from 'peers' if it's dead.
 */
void Cserver::append_update_peer(std::string& d, t_file& file, t_peers::iterator candidate)
{
	unsigned char flags = 0;

	//*_ Fill the update buffer.
	boost::array<char, UPDATE_PEER_SIZE> v;
	if(candidate->second.dead == true)
		flags |= FL_UPDATE_PEER_NEG;
	memcpy(&v.front(), &flags, 1);
	memcpy(&v.front() + 1, &candidate->first.host_, 4);
	memcpy(&v.front() + 5, &candidate->second.port, 2);
	// TODO: Do I need an extended UPDATE? (if so, add code here)
	d.append(v.begin(), v.end());

	//*_ Add candidate to the sent_dead_peers vector of the targeted trackers.
	if(candidate->second.dead == true)
	{
		if(file.b_swarm_leader && file.swarm_leader || file.b_swarm_leader_ext && file.swarm_leader_ext)
			file.swarm_leader->sent_dead_peers[file.swarm_leader->n_sent_dead_peers++] = candidate;
		else
		{
			for(set<t_tracker *>::iterator i = file.trackers.begin(); i != file.trackers.end(); i++)
				(*i)->sent_dead_peers[(*i)->n_sent_dead_peers++] = candidate;
		}
	}
}

/**
 *_ Returns an update for a single swarm referenced in 'rFile'.
 */
std::string Cserver::build_update(t_files::iterator itFile, bool externalDest = false)
{
	typedef std::vector<t_peers::iterator> t_candidates;

	//*_ Make a list with all candidates
	t_candidates candidates;
	for(t_peers::iterator i = itFile->second.peers.begin(); i != itFile->second.peers.end(); i++)
	{
		if( /*(time() - i->second.mtime > m_config.m_announce_interval
			|| logic_xor(i->second.dirty == true, i->second.dead == true))
			&&*/
			externalDest && itFile->second.b_swarm_leader_ext && itFile->second.swarm_leader_ext == NULL
			||	!externalDest && itFile->second.b_swarm_leader && itFile->second.swarm_leader == NULL
			||	(i->second.origin == PO_OWN
			||	externalDest && i->second.origin == PO_INTERNAL || !externalDest && i->second.origin == PO_EXTERNAL) )
		{
			candidates.push_back(i);
		}
	}

	unsigned char n_peers = (unsigned char)std::min((int)candidates.size(), 50); //*_ number of peers in this swarm
	std::string d;
	d.reserve(50 * UPDATE_PEER_SIZE);

	//*_ Swarm header
	char swarm_header[21];
	memcpy(swarm_header, itFile->first.data(), 20);
	memcpy(swarm_header + 20, &n_peers, 1);
	d.append(swarm_header, 21);

	//*_ Append each peer information into the packet
	if (candidates.size() > 50)
	{
		for(int c = 0; c < 50; c++)
		{
			int i = rand() % candidates.size();

			append_update_peer(d, itFile->second, candidates[i]);

			candidates[i] = candidates.back();
			candidates.pop_back();
		}
	}
	else
	{
		for(int i = 0; i < candidates.size(); i++)
			append_update_peer(d, itFile->second, candidates[i]);
	}

	return d;
}

/**
 *_ Fills the update payload variable for each tracker.
 */
void Cserver::build_updates()
{
	cout << "*** build updates\n";

	BOOST_FOREACH(t_trackers::reference rTracker, m_trackers)
	{
		rTracker.second.update.clear();
		rTracker.second.output_transaction_ids[TR_UPDATE] = rand();
	}

	string update;
	string update_ext;
	for(t_files::iterator itFile = m_files.begin(); itFile != m_files.end(); itFile++)
	{
		//*_ I am alone in the swarm.
		if(itFile->second.trackers.empty())
			continue;

		//*_ Build internal and external update for this swarm.
		update = build_update(itFile);
		update_ext = build_update(itFile, true);
		//DEB
		cout << "Send update: ";
		printStrHex(update);

		//*_ Swarm leader dies.
		if(itFile->second.swarm_leader && itFile->second.swarm_leader->status == ST_DISCONNECTED)
		{
			itFile->second.b_swarm_leader = false;
			itFile->second.swarm_leader = NULL;
		}
		if(itFile->second.swarm_leader_ext && itFile->second.swarm_leader_ext->status == ST_DISCONNECTED)
		{
			itFile->second.b_swarm_leader_ext = false;
			itFile->second.swarm_leader_ext = NULL;
		}

		//*_ Update distribution in the swarm
		for(set<t_tracker *>::iterator i = itFile->second.trackers.begin(); i != itFile->second.trackers.end(); i++)
		{
			t_tracker *tracker = *i;

			//*_ internal
			if(!tracker->external)
			{
				if( itFile->second.b_swarm_leader && itFile->second.swarm_leader)
				{
					if(tracker->status & ST_CONNECTED && (tracker->status & ST_PENDING || tracker->status & ST_SUMMARY))
					{
						tracker->update += update;
					}
				}
				else
				{
					if(!tracker->external && (!itFile->second.b_swarm_leader || itFile->second.swarm_leader == NULL
							|| itFile->second.swarm_leader && itFile->second.swarm_leader->status & ST_PENDING) )
					{
						tracker->update += update;
					}
				}
			}
			//*_ external
			else
			{
				if( itFile->second.b_swarm_leader_ext && itFile->second.swarm_leader_ext)
				{
					if(tracker->status & ST_CONNECTED && (tracker->status & ST_PENDING || tracker->status & ST_SUMMARY))
					{
						tracker->update += update_ext;
					}
				}
				else
				{
					if(tracker->external && (!itFile->second.b_swarm_leader_ext || itFile->second.swarm_leader_ext == NULL
							|| itFile->second.swarm_leader_ext && itFile->second.swarm_leader_ext->status & ST_PENDING) )
					{
						tracker->update += update_ext;
					}
				}
			}
		}
		if(itFile->second.b_swarm_leader && itFile->second.swarm_leader)
		{
			//*_ Send updates to the swarm leader.
			itFile->second.swarm_leader->update += update;
			cout << "*** updates to internal swarm leader\n";//DEB
		}
		//DEB
		else
			cout << "*** updates to everyone\n";//DEB
		if(itFile->second.b_swarm_leader_ext && itFile->second.swarm_leader_ext)
		{
			//*_ Send updates to the swarm leader.
			itFile->second.swarm_leader_ext->update += update_ext;
			cout << "*** updates to external swarm leader\n";//DEB
		}
		//DEB
		else
			cout << "*** updates to everyone\n";//DEB

		// OBSOLETE!!!
		//*_ I am the swarm leader or there is no leader or the link to the leader is in PENDING status.
/*		if(!itFile->second.b_swarm_leader || itFile->second.swarm_leader == NULL
				|| itFile->second.swarm_leader && itFile->second.swarm_leader->status & ST_PENDING)
		{
			//*_ Send updates to each tracker in the swarm.
			for(set<t_tracker *>::iterator i = itFile->second.trackers.begin(); i != itFile->second.trackers.end(); i++)
				(*i)->update += update;
		}
		//*_ I am NOT the swarm leader and we have a swarm leader.
		else if(itFile->second.b_swarm_leader && itFile->second.swarm_leader)
		{
			//*_ Send updates to the swarm leader.
			itFile->second.swarm_leader->update += update;

			//*_ Send updates to the links in PENDING or SUMMARY status.
			for(set<t_tracker *>::iterator i = itFile->second.trackers.begin(); i != itFile->second.trackers.end(); i++)
			{
				if( (*i)->status & ST_CONNECTED && ((*i)->status & ST_PENDING || (*i)->status & ST_SUMMARY) )
				{
					(*i)->update += update;
				}
			}

			cout << "*** swarm updates builded\n";//DEB
		}*/
	}
}

/**
 *_ A web page were swarms' information can be viewed.
 */
std::string Cserver::swarms_webpage() const
{
	std::ostringstream os;
	int n;
	os << "<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.0 Transitional//EN\" \"http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd\">"
		<< "<http><head><meta http-equiv=refresh content=60><title>Swarms -- "
		<< m_config.m_tracker_name << ", XBT Unified Tracker</title>"
		<< "<style type='text/css'>th, td {padding-left:16px; text-align:left;}</style>"
		<< "</head><body>";

	os << "<h1>Swarm List</h1>"
		<< "<table><tr><th></th><th>Info hash</th></tr>";
	n = 1;
	BOOST_FOREACH(t_files::const_reference i, m_files)
	{
		os << "<tr><td>" << n << "</td><td><a href='#" << hex_encode(i.first) << "'>"
			<< hex_encode_spaces(i.first) << "</a></td><td></tr>";
		n++;
	}
	os << "</table>";

	os << "<h1>Swarms</h1>";
	n = 1;
	time_t t = time();
	struct tm * timeinfo;
	bool printable;
	//*_ Every swarm
	BOOST_FOREACH(t_files::const_reference i, m_files)
	{
		timeinfo = localtime ( &i.second.ctime );

		os	<< "<h2><a name='" << hex_encode(i.first) << "'>" << n << ". " << hex_encode_spaces(i.first) << "</a></h2><table>"
			<< "<tr><th>Info hash</th><td>" << hex_encode_spaces(i.first) << "</td></tr>"
			<< "<tr><th>Database ID</th><td>" << i.second.fid << "</td></tr>"
			<< "<tr><th>Creation time</th><td>" << asctime(timeinfo) << "</td></tr>"
			<< "<tr><th>Completed</th><td>" << i.second.completed << "</td></tr>"
			<< "<tr><th>Leechers</th><td>" << i.second.leechers << "</td></tr>"
			<< "<tr><th>Seeders</th><td>" << i.second.seeders << "</td></tr>"
			<< "<tr><th>Peers</th><td><a href='#" << hex_encode(i.first) << "_peers'>[see bellow]</a></td></tr>"
			<< "<tr><th>Trackers</th><td><a href='#" << hex_encode(i.first) << "_trackers'>[see bellow]</a></td></tr>";
		os	<< "<tr><th>Internal swarm leader</th><td>";
		if(!i.second.b_swarm_leader)
			os << "(N/A)";
		else
		{
			if(i.second.swarm_leader != NULL)
				os << "Tracker <a href='#" << hex_encode(i.first) << "_" << uri_encode(i.second.swarm_leader->name) << "'>"
					<< i.second.swarm_leader->name << "</a>, host "
					<< i.second.swarm_leader->str_host << " (" << Csocket::inet_ntoa(i.second.swarm_leader->host) << "), port "
					<< i.second.swarm_leader->port;
			else
				os	<< "(this tracker)";
		}
		os << "</td></tr>";
		os	<< "<tr><th>External swarm leader</th><td>";
		if(!i.second.b_swarm_leader_ext)
			os << "(N/A)";
		else
		{
			if(i.second.swarm_leader_ext != NULL)
				os << "Tracker <a href='#" << hex_encode(i.first) << "_" << uri_encode(i.second.swarm_leader_ext->name) << "'>"
					<< i.second.swarm_leader_ext->name << "</a>, host "
					<< i.second.swarm_leader_ext->str_host << " (" << Csocket::inet_ntoa(i.second.swarm_leader_ext->host) << "), port "
					<< i.second.swarm_leader_ext->port;
			else
				os	<< "(this tracker)";
		}
		os << "</td></tr>";
		os	<< "<tr><th>Dirty</th><td>" << (i.second.dirty ? "yes" : "no") << "</td></tr>"
		<< "<tr><th>New arrivals</th><td>" << (i.second.new_arrivals ? "yes" : "no") << "</td></tr>"
		<< "</table>";

		//*_ Every peer of the swarm
		os	<< "<h3><a name='" << hex_encode(i.first) << "_peers'>Peers</a></h3>";
		 if(!i.second.peers.empty()) // if we have peers
		 {
		os	<< "<table>"
			<< "<tr><th>host</th><th>port</th><th>mtime</th><th>downloaded</th><th>uploaded</th><th>left</th><th>origin</th><th>dead</th><th>src tracker</th><th>peer id</th><th>uid</th>"
			;
		BOOST_FOREACH(t_peers::const_reference j, i.second.peers)
		{
			//*_ Check if peer_id is printable
			printable = true;
			for(int k=0; k<20; k++)
				if(!isprint( *(j.second.peer_id.begin() + k) ))
				{
					printable = false;
					break;
				}

			os	<< "<tr>"
				<< "<td>" << Csocket::inet_ntoa(j.first.host_) << "</td>"
				<< "<td>" << ntohs(j.second.port) << "</td>"
				<< "<td>" << t - j.second.mtime << "</td>"
				<< "<td>" << j.second.downloaded << "</td>"
				<< "<td>" << j.second.uploaded << "</td>"
				<< "<td>" << (j.second.left ? "yes" : "no") << "</td>";
			if(j.second.origin == PO_OWN)
				os << "<td>own</td>";
			else if(j.second.origin == PO_INTERNAL)
				os << "<td>internal</td>";
			else if(j.second.origin == PO_EXTERNAL)
				os << "<td>external</td>";
			os	<< "<td>" << (j.second.dead ? "yes" : "no") << "</td>";
			if(j.second.tracker != NULL)
				os	<< "<td><a href='#" << hex_encode(i.first) << "_" << uri_encode(j.second.tracker->name) << "'>" << j.second.tracker->name
					<< "</a></td>";
			else
				os << "<td>-</td>";
			os << "<td>";
			if(j.second.origin == PO_OWN)
			{
				if(printable)
					os	<< string(j.second.peer_id.begin(), j.second.peer_id.end());
				else
					os	<< hex_encode_spaces(string(j.second.peer_id.begin(), j.second.peer_id.end()));
			}
			os << "</td>";
			os	<< "<td>" << j.second.uid << "</td>"
				<< "</tr>";
		}// for each peer
		os	<< "</table>";
		 }// if we have peers
		 else
		 	os << "(no peers)";

		//*_ Every neighbor tracker from the swarm
		os	<< "<h3><a name='" << hex_encode(i.first) << "_trackers'>Trackers</a></h3>";
		 if(!i.second.trackers.empty()) // if we have neighbor trackers
		 {
		os	<< "<table>"
			<< "<tr><th>name</th><th>host</th><th>port</th><th>connected</th></tr>"
			;
		for(set<t_tracker *>::const_iterator j = i.second.trackers.begin(); j != i.second.trackers.end(); j++)
		{
			os	<< "<tr><td><a name='" << hex_encode(i.first) << "_" << uri_encode((*j)->name) << "' href='trackers#"
					<< uri_encode((*j)->name) << "' target='_blank'>" << (*j)->name << "</a></td>"
				<< "<td>" << (*j)->str_host << " (" << Csocket::inet_ntoa((*j)->host) << ")</td>"
				<< "<td>" << (*j)->port << "</td>"
				<< "<td>" << ( (*j)->status & ST_CONNECTED ? "yes" : "no") << "</td></tr>"
				;
		}
		os << "</table>";
		 } // if we have neighbor trackers
		 else
		 	os << "(no neighbor trackers)";
	}

	os << "</body></html>";
	return os.str();
}

/**
 *_ A web page were trackers' information can be viewed.
 */
std::string Cserver::trackers_webpage() const
{
	std::ostringstream os;
	int n;
	time_t t = time();
	os << "<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.0 Transitional//EN\" \"http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd\">"
		<< "<http><head><meta http-equiv=refresh content=60><title>Trackers -- "
		<< m_config.m_tracker_name << ", XBT Unified Tracker</title>"
		<< "<style type='text/css'>th, td {padding-left:16px; text-align:left;}</style>"
		<< "</head><body>";

	os << "<h1>Tracker List</h1>"
		<< "<table><tr><th></th><th>Name</th><th>Host</th><th>Port</th><th>Connected</th></tr>";
	n = 1;
	BOOST_FOREACH(t_trackers::const_reference i, m_trackers)
	{
		os << "<tr><td>" << n << "</td><td><a href='#" << uri_encode(i.second.name) << "'>" << i.second.name << "</a></td><td>"
			<< i.second.str_host << " (" << Csocket::inet_ntoa(i.first.host) << ")</td><td>" << i.first.port << "</td>"
			<< "<td>" << (i.second.status & ST_CONNECTED ? "yes" : " no") << "</td>" "</tr>";
		n++;
	}
	os << "</table>";

	os << "<h1>Trackers</h1>";
	n = 1;
	string status;
	string sent_dead_peers;
	BOOST_FOREACH(t_trackers::const_reference i, m_trackers)
	{
		if(i.second.status == ST_DISCONNECTED)
			status = "(disconnected)";
		else
		{
			if(i.second.status & ST_CONNECTED)
				status += "CONNECTED | ";
			if(i.second.status & ST_PENDING)
			{
				status += "PENDING ";
				if(i.second.status & ST_CONNECTED)
					status += "(sending SUMMARY) | ";
				else
					status += "(recently disconnected) | ";
			}
			if(i.second.status & ST_SYN)
				status += "SYNCHRONIZING (sending SYN-ACK) | ";
			if(i.second.status & ST_SUMMARY)
				status += "SUMMARY (received) | ";
			if(i.second.status & ST_UPDATING)
				status += "UPDATING";
		}

		for(int k=0; k<i.second.n_sent_dead_peers; k++)
			sent_dead_peers += Csocket::inet_ntoa(i.second.sent_dead_peers[k]->first.host_) + ", ";

		os << "<h2><a name='" << uri_encode(i.second.name) << "'>" << n << ". " << i.second.name << "</a></h2><table>"
			<< "<tr><th>Database ID</th><td>" << i.second.tid << "</td></tr>"
			<< "<tr><th>Name</th><td>" << i.second.name << "</td></tr>"
			<< "<tr><th>Host</th><td>" << i.second.str_host << " ("
				<< Csocket::inet_ntoa(i.second.host) << ")</td></tr>"
			<< "<tr><th>Port</th><td>" << i.second.port << "</td></tr>";
		if(i.second.nat)
			os << "<th>NAT port</th><td>" << i.second.nat_port << "</td></tr>";
		else
			os << "<tr><th>No NAT</th></tr>";
		os
			<< "<tr><th>Description</th><td>" << i.second.description << "</td></tr>"
			<< "<tr><th>External</th><td>" << (i.second.external ? "yes" : "no") << "</td></tr>"
			<< "<tr><th>Status</th><td>" << status << "</td></tr>"
			<< "<tr><th>Border tracker</th><td>" << (i.second.border_tracker ? "yes" : "no") << "</td></tr>"
			<< "<tr><th>Receive time</th><td>" << t - i.second.recv_time << "</td></tr>"
			<< "<tr><th>Reconnect time</th><td>" << t - i.second.reconnect_time << "</td></tr>"
			<< "<tr><th>Delayed SYN</th><td>" << (i.second.delay ? "yes" : "no") << "</td></tr>"
			<< "<tr><th>Retry times</th><td>" << i.second.retry_times << "</td></tr>"
			<< "<tr><th>Connection ID</th><td>" << i.second.connection_id << "</td></tr>"
			<< "<tr><th>Mandates</th><td>";
		if(i.second.mandates == INT_MAX)
			os << "(N/A)";
		else
			os << i.second.mandates;
		os	<< "</td></tr>"
			<< "<tr><th>UPDATE buffer</th><td>" << hex_encode_spaces(const_memory_range(i.second.update)) << "</td></tr>"
			<< "<tr><th>SUMMARY buffer</th><td>" << hex_encode_spaces(const_memory_range(i.second.summary)) << "</td></tr>"
			<< "<tr><th>LEADER buffer</th><td>" << hex_encode_spaces(const_memory_range(i.second.leader)) << "</td></tr>"
			<< "<tr><th>Pending ACK for sent dead peers</th><td>" << sent_dead_peers << "</td></tr>"
			;
		os << "</table>";

		n++;
		status.clear();
		sent_dead_peers.clear();
	}

	os << "</body></html>";
	return os.str();
}

/**
 *_ Initialize the election campaign, by marking to the trackers to communicate CANDIDATURE packets.
 *_ The notifier tracker is the one who started the election process. If NULL, I'm that tracker.
 */
void Cserver::init_election_campaign(t_tracker *notifier = NULL)
{
	if(m_election_campaign)
		return;
	start_election_campaign();

	if(m_files.empty())
			return;

	m_n_send_candidature = 0;
	m_n_recv_candidature = 0;
	// for each swarm
	for(t_files::iterator it = m_files.begin(); it != m_files.end(); it++)
	{
		// for each tracker in the swarm
		for(set<t_tracker *>::iterator itTracker = it->second.trackers.begin(); itTracker != it->second.trackers.end(); itTracker++)
		{
			if( ( (*itTracker)->status & ST_CONNECTED ) == 0)
				continue;

			if( ((*itTracker)->status & ST_SEND_CANDIDATURE) == 0)
			{
				cout << "*** ST_SEND_CANDIDATURE " << Csocket::inet_ntoa((*itTracker)->host) << "\n";
				(*itTracker)->status |= ST_SEND_CANDIDATURE;
				m_n_send_candidature++;
			}
			if( ((*itTracker)->status & ST_RECV_CANDIDATURE) == 0 && notifier != (*itTracker))
			{
				cout << "*** ST_RECV_CANDIDATURE " << Csocket::inet_ntoa((*itTracker)->host) << "\n";
				(*itTracker)->status |= ST_RECV_CANDIDATURE;
				m_n_recv_candidature++;
			}
		}
	}
}

/**
 *_ Called at the end of the election process, this method chooses the swarm leaders for the specified swarms.
 */
void Cserver::choose_swarm_leaders()
{
	if(m_files.empty())
		return;

	// for each swarm
	for(t_files::iterator it = m_files.begin(); it != m_files.end(); it++)
	{
		t_file &file = it->second;

		if(file.b_swarm_leader)
		{
			if(file.swarm_leader != NULL)
				file.swarm_leader->mandates--;
			else
				m_mandates--;
		}
		if(file.b_swarm_leader_ext)
		{
			if(file.swarm_leader_ext != NULL)
				file.swarm_leader_ext->mandates--;
			else
				m_mandates--;
		}

		t_tracker *minInt = NULL;
		t_tracker *minExt = NULL;
		// for each tracker in the swarm
		for(set<t_tracker *>::iterator itTracker = file.trackers.begin(); itTracker != file.trackers.end(); itTracker++)
		{
			//*_ internal
			if( !(*itTracker)->external )
			{
				if(minInt == NULL)
				{
					minInt = *itTracker;
					file.b_swarm_leader = true;
					continue;
				}
				if( 		(*itTracker)->mandates < minInt->mandates
						||	(*itTracker)->mandates == minInt->mandates && (*itTracker)->host < minInt->host
						||	(*itTracker)->mandates == minInt->mandates && (*itTracker)->host == minInt->host && (*itTracker)->port < minInt->port)
				{
					minInt = *itTracker;
				}
			}
			//*_ external
			else
			{
				if(minExt == NULL)
				{
					minExt = *itTracker;
					file.b_swarm_leader_ext = true;
					continue;
				}
				if( 		(*itTracker)->mandates < minExt->mandates
						||	(*itTracker)->mandates == minExt->mandates && (*itTracker)->host < minExt->host
						||	(*itTracker)->mandates == minExt->mandates && (*itTracker)->host == minExt->host && (*itTracker)->port < minExt->port)
				{
					minExt = *itTracker;
				}
			}
		}
		//*_ compare with me also
		//*_	internal
		if(minInt&& (m_mandates < minInt->mandates
				||	m_mandates == minInt->mandates && Csocket::get_host(m_config.m_ip) < minInt->host
				||	m_mandates == minInt->mandates && Csocket::get_host(m_config.m_ip) == minInt->host && m_tsup_port < minInt->port) )
		{
			minInt = NULL;
		}
		//*_	external
		if(minExt&&	(m_mandates < minExt->mandates
				||	m_mandates == minExt->mandates && Csocket::get_host(m_config.m_ip) < minExt->host
				||	m_mandates == minExt->mandates && Csocket::get_host(m_config.m_ip) == minExt->host && m_tsup_port < minExt->port) )
		{
			minExt = NULL;
		}

		//*_ Set the new leaders and update their mandates.
		//*_	internal
		if(minInt)
			minInt->mandates++;
		else
		{
			if(file.b_swarm_leader)
				m_mandates++;
		}
		file.swarm_leader = minInt;
		//*_	external
		if(minExt)
			minExt->mandates++;
		else
			if(file.b_swarm_leader_ext)
				m_mandates++;
		file.swarm_leader_ext = minExt;
		file.new_arrivals = false;
	}

	cout << "*** choose_swarm_leaders\n";
}

void Cserver::new_border_tracker(t_tracker &tracker)
{
	for(t_files::iterator it = m_files.begin(); it != m_files.end(); it++)
		unify_swarm(it->first, &tracker);

	tracker.border_tracker = true;
}

/**
 * Inserts a new peer or updates peer information from the peer list for a specific file (torrent).
 * If restrictions are faulted it return an error message, otherwise it returns a null string.
 */
std::string Cserver::insert_peer(const Ctracker_input& v, bool udp, t_user* user)
{
	cout << "*** insert_peers\n";//DEB

	if (m_use_sql && m_config.m_log_announce)
	{
		m_announce_log_buffer += Csql_query(m_database, "(?,?,?,?,?,?,?,?,?,?),")
			.p(ntohl(v.m_ipa)).p(ntohs(v.m_port)).p(v.m_event).p(v.m_info_hash).p(v.m_peer_id).p(v.m_downloaded).p(v.m_left).p(v.m_uploaded).p(user ? user->uid : 0).p(time()).read();
	}

	//*_ Send a SUMMARY packet to every tracker if a new torrent file is registered.
	bool b_new_file = !file(v.m_info_hash);
	if(b_new_file)
	{
		report_new_file(v.m_info_hash);
	}

	// ** Error messages.
	if (!m_config.m_offline_message.empty())
		return m_config.m_offline_message;
	if (!m_config.m_anonymous_announce && !user)
		return bts_unregistered_torrent_pass;
	if (!m_config.m_auto_register && b_new_file)
		return bts_unregistered_torrent;
	if (v.m_left && user && !user->can_leech)
		return bts_can_not_leech;

	// ** Access/add a file.
	t_file& file = m_files[v.m_info_hash];
	// ** If a new file was added, initialize the creation time.
	if (!file.ctime)
		file.ctime = time();
	// ** wait_time error message.
	if (v.m_left && user && user->wait_time && file.ctime + user->wait_time > time())
		return bts_wait_time;

	t_peers::key_type peer_key(v.m_ipa, user ? user->uid : 0);
	t_peers::iterator i = file.peers.find(peer_key);
	// ** If the peer already exists.
	// ** (the variables decremented will be incremented back latter)
	if (i != file.peers.end())
	{
		(i->second.left ? file.leechers : file.seeders)--;
		if (t_user* old_user = find_user_by_uid(i->second.uid))
			(i->second.left ? old_user->incompletes : old_user->completes)--;
	}
	// ** Torrents limit reached error message.
	else if (v.m_left && user && user->torrents_limit && user->incompletes >= user->torrents_limit)
		return bts_torrents_limit_reached;
	// ** Peers limit reached error message.
	else if (v.m_left && user && user->peers_limit)
	{
		int c = 0;
		BOOST_FOREACH(t_peers::reference j, file.peers)
			c += j.second.left && j.second.uid == user->uid;
		if (c >= user->peers_limit)
			return bts_peers_limit_reached;
	}

	// ** Information for updating the *_users DB table.
	if (m_use_sql && user && file.fid)
	{
		long long downloaded = 0;
		long long uploaded = 0;
		if (i != file.peers.end()
			&& boost::equals(i->second.peer_id, v.m_peer_id)
			&& v.m_downloaded >= i->second.downloaded
			&& v.m_uploaded >= i->second.uploaded)
		{
			downloaded = v.m_downloaded - i->second.downloaded;
			uploaded = v.m_uploaded - i->second.uploaded;
		}
		m_files_users_updates_buffer += Csql_query(m_database, "(?,1,?,?,?,?,?,?,?),")
			.p(v.m_event != Ctracker_input::e_stopped)
			.p(v.m_event == Ctracker_input::e_completed)
			.p(downloaded)
			.p(v.m_left)
			.p(uploaded)
			.p(time())
			.p(file.fid)
			.p(user->uid)
			.read();
		if (downloaded || uploaded)
			m_users_updates_buffer += Csql_query(m_database, "(?,?,?),").p(downloaded).p(uploaded).p(user->uid).read();
	}

	// ** Erase the peer if the user chose stop.
	if (v.m_event == Ctracker_input::e_stopped)
	{
		//file.peers.erase(peer_key);// original XBT

		t_peers::iterator itDel;
		//DEB
		for(itDel = file.peers.begin(); itDel != file.peers.end(); itDel++)
			cout << Csocket::inet_ntoa(itDel->first.host_) << " ";
		cout << endl << Csocket::inet_ntoa(peer_key.host_) << endl;

		//*_ Mark the peer dead for future deletion.
		itDel = file.peers.find(peer_key);
		if(itDel != file.peers.end())
		{
			itDel->second.dead = true;
			cout << "*** Delete peer\n";//DEB
		}
	}
	// ** Update the peer information if it didn't stop.
	else
	{
		t_peer& peer = file.peers[peer_key];
		peer.downloaded = v.m_downloaded;
		peer.left = v.m_left;
		std::copy(v.m_peer_id.begin(), v.m_peer_id.end(), peer.peer_id.begin());
		peer.port = v.m_port;
		peer.uid = user ? user->uid : 0;
		peer.uploaded = v.m_uploaded;
		// ** if the peer already exists, the incrementing has no effect because they were decremented earlier.
		(peer.left ? file.leechers : file.seeders)++;
		if (user)
			(peer.left ? user->incompletes : user->completes)++;
		peer.mtime = time();

		//*_ TSUP members
		peer.origin = PO_OWN;
		peer.dead = false;
		peer.tracker = NULL;
		peer.file = &file;
	}

	if (v.m_event == Ctracker_input::e_completed)
		file.completed++;
	(udp ? m_stats.announced_udp : m_stats.announced_http)++;
	file.dirty = true;

	// ** No error (success).
	return "";
}

/**
 * Selects the number of peers requested in an announce and returns them in binary compact representation in accordance with the BT specification.
 * A number of maximum 50 peers are allowed.
 */
std::string Cserver::t_file::select_peers(const Ctracker_input& ti) const
{
	cout << "*** num_want = " << ti.m_num_want << endl;//DEB
	if (ti.m_event == Ctracker_input::e_stopped)
		return "";

	typedef std::vector<boost::array<char, 6> > t_candidates;

	t_candidates candidates;
	BOOST_FOREACH(t_peers::const_reference i, peers)
	{
		//*_ Dead peers are not reported to clients.
		if (i.second.dead)
			continue;
		if (!ti.m_left && !i.second.left)
			continue;
		boost::array<char, 6> v;
		memcpy(&v.front(), &i.first.host_, 4);
		memcpy(&v.front() + 4, &i.second.port, 2);
		candidates.push_back(v);

		//DEB
		cout << "*** peer: ";
		printStrHex(string(v.begin(), v.end()));
	}
	size_t c = ti.m_num_want < 0 ? 50 : std::min(ti.m_num_want, 50);
	std::string d;
	d.reserve(300);
	if (candidates.size() > c)
	{
		while (c--)
		{
			int i = rand() % candidates.size();
			d.append(candidates[i].begin(), candidates[i].end());
			candidates[i] = candidates.back();
			candidates.pop_back();
		}
	}
	else
	{
		BOOST_FOREACH(t_candidates::reference i, candidates)
			d.append(i.begin(), i.end());
	}

	//DEB
	cout << "*** selected peers: ";
	printStrHex(d);
	return d;
}

Cvirtual_binary Cserver::select_peers(const Ctracker_input& ti) const
{
	const t_file* f = file(ti.m_info_hash);
	if (!f)
		return Cvirtual_binary();
	std::string peers = f->select_peers(ti);
	return Cvirtual_binary((boost::format("d8:completei%de10:incompletei%de8:intervali%de12:min intervali%de5:peers%d:%se")
		% f->seeders % f->leechers % config().m_announce_interval % config().m_announce_interval % peers.size() % peers).str());
}

void Cserver::t_file::clean_up(time_t t, Cserver& server)
{
	for (t_peers::iterator i = peers.begin(); i != peers.end(); )
	{
		//DEB
		if (i->second.mtime < t)
		{
			(i->second.left ? leechers : seeders)--;
			if (t_user* user = server.find_user_by_uid(i->second.uid))
				(i->second.left ? user->incompletes : user->completes)--;
			if (i->second.uid)
				server.m_files_users_updates_buffer += Csql_query(server.m_database, "(0,0,0,0,-1,0,-1,?,?),").p(fid).p(i->second.uid).read();

			//*_ Erase old dead peers
			if(i->second.dead)
				peers.erase(i++);
			else
			//*_ Mark as dead for future deletion.
			{
				cout << "asta ^" << endl;//DEB

				if(i->second.origin == PO_INTERNAL && !server.m_external || i->second.origin == PO_EXTERNAL && !server.m_internal)
				{
					peers.erase(i++);
				}
				else
				{
					i->second.dead = true;
					i->second.mtime = ::time(NULL);
					i++;
				}
			}

			dirty = true;
		}
		else
			i++;
	}
}

void Cserver::clean_up()
{
	BOOST_FOREACH(t_files::reference i, m_files)
		i.second.clean_up(time() - static_cast<int>(1.5 * m_config.m_announce_interval), *this);
	m_clean_up_time = time();
}

static byte* write_compact_int(byte* w, unsigned int v)
{
	if (v >= 0x200000)
	{
		*w++ = 0xe0 | (v >> 24);
		*w++ = v >> 16;
		*w++ = v >> 8;
	}
	else if (v >= 0x4000)
	{
		*w++ = 0xc0 | (v >> 16);
		*w++ = v >> 8;
	}
	else if (v >= 0x80)
		*w++ = 0x80 | (v >> 8);
	*w++ = v;
	return w;
}

Cvirtual_binary Cserver::scrape(const Ctracker_input& ti)
{
	if (m_use_sql && m_config.m_log_scrape)
	{
		Csql_query q(m_database, "(?,?,?),");
		q.p(ntohl(ti.m_ipa));
		if (ti.m_info_hash.empty())
			q.p_raw("null");
		else
			q.p(ti.m_info_hash);
		q.p(time());
		m_scrape_log_buffer += q.read();
	}
	std::string d;
	d += "d5:filesd";
	if (ti.m_info_hashes.empty())
	{
		m_stats.scraped_full++;
		if (ti.m_compact)
		{
			Cvirtual_binary d;
			byte* w = d.write_start(32 * m_files.size() + 1);
			*w++ = 'x';
			BOOST_FOREACH(t_files::reference i, m_files)
			{
				if (!i.second.leechers && !i.second.seeders)
					continue;
				memcpy(w, i.first.data(), i.first.size());
				w += i.first.size();
				w = write_compact_int(w, i.second.seeders);
				w = write_compact_int(w, i.second.leechers);
				w = write_compact_int(w, i.second.completed);
			}
			d.resize(w - d);
			return d;
		}
		d.reserve(90 * m_files.size());
		BOOST_FOREACH(t_files::reference i, m_files)
		{
			if (i.second.leechers || i.second.seeders)
				d += (boost::format("20:%sd8:completei%de10:downloadedi%de10:incompletei%dee") % i.first % i.second.seeders % i.second.completed % i.second.leechers).str();
		}
	}
	else
	{
		m_stats.scraped_http++;
		BOOST_FOREACH(Ctracker_input::t_info_hashes::const_reference j, ti.m_info_hashes)
		{
			t_files::const_iterator i = m_files.find(j);
			if (i != m_files.end())
				d += (boost::format("20:%sd8:completei%de10:downloadedi%de10:incompletei%dee") % i->first % i->second.seeders % i->second.completed % i->second.leechers).str();
		}
	}
	d += "e";
	if (m_config.m_scrape_interval)
		d += (boost::format("5:flagsd20:min_request_intervali%dee") % m_config.m_scrape_interval).str();
	d += "e";
	return Cvirtual_binary(d);
}

void Cserver::read_db_deny_from_hosts()
{
	m_read_db_deny_from_hosts_time = time();
	if (!m_use_sql)
		return;
	try
	{
		Csql_result result = Csql_query(m_database, "select begin, end from ?").p_name(table_name(table_deny_from_hosts)).execute();
		BOOST_FOREACH(t_deny_from_hosts::reference i, m_deny_from_hosts)
			i.second.marked = true;
		for (Csql_row row; row = result.fetch_row(); )
		{
			t_deny_from_host& deny_from_host = m_deny_from_hosts[row[1].i()];
			deny_from_host.marked = false;
			deny_from_host.begin = row[0].i();
		}
		for (t_deny_from_hosts::iterator i = m_deny_from_hosts.begin(); i != m_deny_from_hosts.end(); )
		{
			if (i->second.marked)
				m_deny_from_hosts.erase(i++);
			else
				i++;
		}
	}
	catch (Cdatabase::exception&)
	{
	}
}

void Cserver::read_db_files()
{
	m_read_db_files_time = time();
	if (m_use_sql)
		read_db_files_sql();
	else if (!m_config.m_auto_register)
	{
		std::set<std::string> new_files;
		std::ifstream is("xbt_files.txt");
		std::string s;
		while (getline(is, s))
		{
			s = hex_decode(s);
			if (s.size() != 20)
				continue;

			m_files[s];

			//*_ Report the new file.
			if(m_files.find(s) != m_files.end())
				report_new_file(s);

			new_files.insert(s);
		}
		for (t_files::iterator i = m_files.begin(); i != m_files.end(); )
		{
			if (new_files.find(i->first) == new_files.end())
			{
				//*_ Report the deletion of the file
				report_delete_file(i->first);

				m_files.erase(i);

				i++;
			}
			else
				i++;
		}
	}
}

void Cserver::read_db_files_sql()
{
	try
	{
		if (!m_config.m_auto_register)
		{
			Csql_result result = Csql_query(m_database, "select info_hash, ? from ? where flags & 1").p_name(column_name(column_files_fid)).p_name(table_name(table_files)).execute();
			for (Csql_row row; row = result.fetch_row(); )
			{
				t_files::iterator i = m_files.find(row[0].s());
				if (i != m_files.end())
				{
					BOOST_FOREACH(t_peers::reference j, i->second.peers)
					{
						if (t_user* user = find_user_by_uid(j.second.uid))
							(j.second.left ? user->incompletes : user->completes)--;
					}

					//*_ Send a SUMMARY packet to every tracker because a torrent file has been deleted.
					report_delete_file(i->first);

					m_files.erase(i);
				}
				Csql_query(m_database, "delete from ? where ? = ?").p_name(table_name(table_files)).p_name(column_name(column_files_fid)).p(row[1].i()).execute();
			}
		}

		// ** If no files are stored in the tracker reset leechers and seeders columns from the *_files DB table.
		if (m_files.empty())
			m_database.query("update " + table_name(table_files) + " set " + column_name(column_files_leechers) + " = 0, " + column_name(column_files_seeders) + " = 0");
		else if (m_config.m_auto_register)
			return;

		// ** If m_file is empty or no auto_register continue:
		// ** Add new files in the tracker.
		Csql_result result = Csql_query(m_database, "select info_hash, ?, ?, ctime from ? where ? >= ?")
			.p_name(column_name(column_files_completed))
			.p_name(column_name(column_files_fid))
			.p_name(table_name(table_files))
			.p_name(column_name(column_files_fid))
			.p(m_fid_end)
			.execute();
		for (Csql_row row; row = result.fetch_row(); )
		{
			m_fid_end = std::max(m_fid_end, static_cast<int>(row[2].i()) + 1);
			if (row[0].size() != 20 || file(row[0].s()))
				continue;
			t_file& file = m_files[row[0].s()];
			if (file.fid)
				continue;
			file.completed = row[1].i();
			file.dirty = false;
			file.fid = row[2].i();
			file.ctime = row[3].i();

			//*_ Send a SUMMARY packet to every tracker because a new torrent file is registered.
			report_new_file(row[0].s());
		}
	}
	catch (Cdatabase::exception&)
	{
	}
}

void Cserver::read_db_users()
{
	m_read_db_users_time = time();
	if (!m_use_sql)
		return;
	try
	{
		Csql_query q(m_database, "select ?");
		if (m_read_users_can_leech)
			q += ", can_leech";
		if (m_read_users_peers_limit)
			q += ", peers_limit";
		if (m_read_users_torrent_pass)
			q += ", torrent_pass";
		if (m_read_users_torrent_pass_version)
			q += ", torrent_pass_version";
		if (m_read_users_torrents_limit)
			q += ", torrents_limit";
		if (m_read_users_wait_time)
			q += ", wait_time";
		q += " from ?";
		q.p_name(column_name(column_users_uid));
		q.p_name(table_name(table_users));
		Csql_result result = q.execute();
		BOOST_FOREACH(t_users::reference i, m_users)
			i.second.marked = true;
		m_users_torrent_passes.clear();
		for (Csql_row row; row = result.fetch_row(); )
		{
			t_user& user = m_users[row[0].i()];
			user.marked = false;
			int c = 0;
			user.uid = row[c++].i();
			if (m_read_users_can_leech)
				user.can_leech = row[c++].i();
			if (m_read_users_peers_limit)
				user.peers_limit = row[c++].i();
			if (m_read_users_torrent_pass)
			{
				if (row[c].size())
					m_users_torrent_passes[row[c].s()] = &user;
				c++;
			}
			if (m_read_users_torrent_pass_version)
				user.torrent_pass_version = row[c++].i();
			if (m_read_users_torrents_limit)
				user.torrents_limit = row[c++].i();
			if (m_read_users_wait_time)
				user.wait_time = row[c++].i();
		}
		for (t_users::iterator i = m_users.begin(); i != m_users.end(); )
		{
			if (i->second.marked)
				m_users.erase(i++);
			else
				i++;
		}
	}
	catch (Cdatabase::exception&)
	{
	}
}

void Cserver::read_db_trackers()
{
	in_addr_t host;
	int port;
	tracker_key *key;
	t_tracker *value;

	Csql_result result = Csql_query(m_database,
			"select tid, name, host, port, description, nat, external from ?").p_name(table_name(table_trackers)).execute();
	for (Csql_row row; row = result.fetch_row(); )
	{
		host = Csocket::get_host(row[2].s());
		port = (int)row[3].i();
		key = new tracker_key(host, port);
		value = new t_tracker();

		//*_ tid
		value->tid = (int)row[0].i();
		//*_ name
		row[1].s().copy(value->name, 255);
		//*_ host
		value->host = host;
		value->str_host.assign(row[2].s());
		//*_ port
		value->port = port;
		//*_ description
		row[4].s().copy(value->description, 255);
		//*_ nat
		value->nat = (bool)row[5].i();
		//*_ external
		value->external = (bool)row[6].i();
		if(value->external)
			m_external = true;
		else
			m_internal = true;

		value->retry_times = m_config.m_retry_times;
		value->delay = generate_delay();

		m_trackers[*key] = *value;
	}
}

void Cserver::write_db_files()
{
	m_write_db_files_time = time();
	if (!m_use_sql)
		return;
	try
	{
		std::string buffer;
		BOOST_FOREACH(t_files::reference i, m_files)
		{
			t_file& file = i.second;
			if (!file.dirty)
				continue;
			if (!file.fid)
			{
				Csql_query(m_database, "insert into ? (info_hash, mtime, ctime) values (?, unix_timestamp(), unix_timestamp())").p_name(table_name(table_files)).p(i.first).execute();
				file.fid = m_database.insert_id();
			}
			buffer += Csql_query(m_database, "(?,?,?,?),").p(file.leechers).p(file.seeders).p(file.completed).p(file.fid).read();
			file.dirty = false;
		}
		if (!buffer.empty())
		{
			buffer.erase(buffer.size() - 1);
			m_database.query("insert into " + table_name(table_files) + " (" + column_name(column_files_leechers) + ", " + column_name(column_files_seeders) + ", " + column_name(column_files_completed) + ", " + column_name(column_files_fid) + ") values "
				+ buffer
				+ " on duplicate key update"
				+ "  " + column_name(column_files_leechers) + " = values(" + column_name(column_files_leechers) + "),"
				+ "  " + column_name(column_files_seeders) + " = values(" + column_name(column_files_seeders) + "),"
				+ "  " + column_name(column_files_completed) + " = values(" + column_name(column_files_completed) + "),"
				+ "  mtime = unix_timestamp()");
		}
	}
	catch (Cdatabase::exception&)
	{
	}
	if (!m_announce_log_buffer.empty())
	{
		try
		{
			m_announce_log_buffer.erase(m_announce_log_buffer.size() - 1);
			m_database.query("insert delayed into " + table_name(table_announce_log) + " (ipa, port, event, info_hash, peer_id, downloaded, left0, uploaded, uid, mtime) values " + m_announce_log_buffer);
		}
		catch (Cdatabase::exception&)
		{
		}
		m_announce_log_buffer.erase();
	}
	if (!m_scrape_log_buffer.empty())
	{
		try
		{
			m_scrape_log_buffer.erase(m_scrape_log_buffer.size() - 1);
			m_database.query("insert delayed into " + table_name(table_scrape_log) + " (ipa, info_hash, mtime) values " + m_scrape_log_buffer);
		}
		catch (Cdatabase::exception&)
		{
		}
		m_scrape_log_buffer.erase();
	}
}

void Cserver::write_db_users()
{
	m_write_db_users_time = time();
	if (!m_use_sql)
		return;
	if (!m_files_users_updates_buffer.empty())
	{
		m_files_users_updates_buffer.erase(m_files_users_updates_buffer.size() - 1);
		try
		{
			m_database.query("insert into " + table_name(table_files_users) + " (active, announced, completed, downloaded, `left`, uploaded, mtime, fid, uid) values "
				+ m_files_users_updates_buffer
				+ " on duplicate key update"
				+ "  active = values(active),"
				+ "  announced = announced + values(announced),"
				+ "  completed = completed + values(completed),"
				+ "  downloaded = downloaded + values(downloaded),"
				+ "  `left` = if(values(`left`) = -1, `left`, values(`left`)),"
				+ "  uploaded = uploaded + values(uploaded),"
				+ "  mtime = if(values(mtime) = -1, mtime, values(mtime))");
		}
		catch (Cdatabase::exception&)
		{
		}
		m_files_users_updates_buffer.erase();
	}
	if (!m_users_updates_buffer.empty())
	{
		m_users_updates_buffer.erase(m_users_updates_buffer.size() - 1);
		try
		{
			m_database.query("insert into " + table_name(table_users) + " (downloaded, uploaded, " + column_name(column_users_uid) + ") values "
				+ m_users_updates_buffer
				+ " on duplicate key update"
				+ "  downloaded = downloaded + values(downloaded),"
				+ "  uploaded = uploaded + values(uploaded)");
		}
		catch (Cdatabase::exception&)
		{
		}
		m_users_updates_buffer.erase();
	}
}

void Cserver::read_config()
{
	if (m_use_sql)
	{
		try
		{
			// from the database
			Csql_result result = m_database.query("select name, value from " + table_name(table_config) + " where value is not null");
			Cconfig config;
			for (Csql_row row; row = result.fetch_row(); )
			{
				if (config.set(row[0].s(), row[1].s()))
					std::cerr << "unknown config name: " << row[0].s() << std::endl;
			}

			// from the config file
			config.load(m_conf_file);

			// Insert torrent_pass_private_key attribute into the *_config table
			if (config.m_torrent_pass_private_key.empty())
			{
				config.m_torrent_pass_private_key = generate_random_string(27);
				Csql_query(m_database, "insert into xbt_config (name, value) values ('torrent_pass_private_key', ?)").p(config.m_torrent_pass_private_key).execute();
			}
			m_config = config;
		}
		catch (Cdatabase::exception&)
		{
		}
	}
	else
	{
		Cconfig config;
		if (!config.load(m_conf_file))
			m_config = config;
	}
	if (m_config.m_listen_ipas.empty())
		m_config.m_listen_ipas.insert(htonl(INADDR_ANY));
	if (m_config.m_listen_ports.empty())
		m_config.m_listen_ports.insert(2710);
	m_read_config_time = time();
}

void Cserver::t_file::debug(std::ostream& os) const
{
	BOOST_FOREACH(t_peers::const_reference i, peers)
	{
		os << "<tr><td>" + Csocket::inet_ntoa(i.first.host_)
			<< "<td align=right>" << ntohs(i.second.port)
			<< "<td align=right>" << i.second.uid
			<< "<td align=right>" << i.second.left
			<< "<td align=right>" << ::time(NULL) - i.second.mtime
			<< "<td>" << hex_encode(const_memory_range(i.second.peer_id.begin(), i.second.peer_id.end()));
	}
}

std::string Cserver::debug(const Ctracker_input& ti) const
{
	std::ostringstream os;
	os << "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01//EN\"><meta http-equiv=refresh content=60><title>"
			<< m_config.m_tracker_name << ", XBT Unified Tracker</title>";
	int leechers = 0;
	int seeders = 0;
	int torrents = 0;
	os << "<table>";
	if (ti.m_info_hash.empty())
	{
		BOOST_FOREACH(t_files::const_reference i, m_files)
		{
			if (!i.second.leechers && !i.second.seeders)
				continue;
			leechers += i.second.leechers;
			seeders += i.second.seeders;
			torrents++;
			os << "<tr><td align=right>" << i.second.fid
				<< "<td><a href=\"?info_hash=" << uri_encode(i.first) << "\">" << hex_encode(i.first) << "</a>"
				<< "<td>" << (i.second.dirty ? '*' : ' ')
				<< "<td align=right>" << i.second.leechers
				<< "<td align=right>" << i.second.seeders;
		}
	}
	else
	{
		t_files::const_iterator i = m_files.find(ti.m_info_hash);
		if (i != m_files.end())
			i->second.debug(os);
	}
	os << "</table>";
	return os.str();
}

std::string Cserver::statistics() const
{
	std::ostringstream os;
	os << "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.01//EN\"><meta http-equiv=refresh content=60><title>"
			<< m_config.m_tracker_name << ", XBT Unified Tracker</title>";
	int leechers = 0;
	int seeders = 0;
	int torrents = 0;
	BOOST_FOREACH(t_files::const_reference i, m_files)
	{
		leechers += i.second.leechers;
		seeders += i.second.seeders;
		torrents += i.second.leechers || i.second.seeders;
	}
	time_t t = time();

	os << "<h1>XBT Tracker General Information</h1>";
	os << "<table><tr><td>leechers<td align=right>" << leechers
		<< "<tr><td>seeders<td align=right>" << seeders
		<< "<tr><td>peers<td align=right>" << leechers + seeders
		<< "<tr><td>torrents<td align=right>" << torrents
		<< "<tr><td>"
		<< "<tr><td>accepted tcp<td align=right>" << m_stats.accepted_tcp
		<< "<tr><td>rejected tcp<td align=right>" << m_stats.rejected_tcp
		<< "<tr><td>announced<td align=right>" << m_stats.announced();
	if (m_stats.announced())
	{
		os << "<tr><td>announced http <td align=right>" << m_stats.announced_http << "<td align=right>" << m_stats.announced_http * 100 / m_stats.announced() << " %"
			<< "<tr><td>announced udp<td align=right>" << m_stats.announced_udp << "<td align=right>" << m_stats.announced_udp * 100 / m_stats.announced() << " %";
	}
	os << "<tr><td>scraped full<td align=right>" << m_stats.scraped_full
		<< "<tr><td>scraped<td align=right>" << m_stats.scraped();
	if (m_stats.scraped())
	{
		os << "<tr><td>scraped http<td align=right>" << m_stats.scraped_http << "<td align=right>" << m_stats.scraped_http * 100 / m_stats.scraped() << " %"
			<< "<tr><td>scraped udp<td align=right>" << m_stats.scraped_udp << "<td align=right>" << m_stats.scraped_udp * 100 / m_stats.scraped() << " %";
	}
	os << "<tr><td>"
		<< "<tr><td>up time<td align=right>" << duration2a(time() - m_stats.start_time)
		<< "<tr><td>"
		<< "<tr><td>anonymous connect<td align=right>" << m_config.m_anonymous_connect
		<< "<tr><td>anonymous announce<td align=right>" << m_config.m_anonymous_announce
		<< "<tr><td>anonymous scrape<td align=right>" << m_config.m_anonymous_scrape
		<< "<tr><td>auto register<td align=right>" << m_config.m_auto_register
		<< "<tr><td>full scrape<td align=right>" << m_config.m_full_scrape
		<< "<tr><td>read config time<td align=right>" << t - m_read_config_time << " / " << m_config.m_read_config_interval
		<< "<tr><td>clean up time<td align=right>" << t - m_clean_up_time << " / " << m_config.m_clean_up_interval
		<< "<tr><td>read db files time<td align=right>" << t - m_read_db_files_time << " / " << m_config.m_read_db_interval;
	if (m_use_sql)
	{
		os << "<tr><td>read db users time<td align=right>" << t - m_read_db_users_time << " / " << m_config.m_read_db_interval
			<< "<tr><td>write db files time<td align=right>" << t - m_write_db_files_time << " / " << m_config.m_write_db_interval
			<< "<tr><td>write db users time<td align=right>" << t - m_write_db_users_time << " / " << m_config.m_write_db_interval;
	}
	os << "</table>";

	os << "<h1>XBT Tracker TSUP Information</h1>";
	os << "<table>"
		<< "<tr><td>hello time</td><td align='right'>" << t - m_hello_time << " / " << m_config.m_hello_interval << "</td></tr>"
		<< "<tr><td>update time</td><td align='right'>" << t - m_update_time << " / " << m_config.m_update_interval << "</td></tr>"
		<< "<tr><td>mandate time</td><td align='right'>" << t - m_mandate_time << " / " << m_config.m_mandate_interval << "</td></tr>"
		<< "<tr><td>disconnect interval</td><td align='right'>" << m_config.m_disconnect_interval << "</td></tr>"
		<< "<tr><td>reconnect interval</td><td align='right'>" << m_config.m_reconnect_interval << "</td></tr>"
		//<< "<tr><td>delay / max delay interval</td><td align='right'>" << m_delay << " / " << m_config.m_max_delay_interval << "</td></tr>"
		<< "<tr><td>retry times</td><td align='right'>" << m_config.m_retry_times << "</td></tr>"
		<< "<tr></tr>"
		<< "<tr><td>neighbor trackers</td><td align='right'>" << m_trackers.size() << "</td></tr>"
		<< "<tr><td>swarms</td><td align='right'>" << m_files.size() << "</td></tr>"
		<< "<tr><td>border tracker</td><td align='right'>" << (border_tracker() ? "yes" : "no") << "</td></tr>"
		<< "<tr><td>mandates</td><td align='right'>" << m_mandates << "</td></tr>"
		<< "</table>";
	border_tracker();
	return os.str();
}

Cserver::t_user* Cserver::find_user_by_torrent_pass(const std::string& v, const std::string& info_hash)
{
	if (t_user* user = find_user_by_uid(read_int(4, hex_decode(v.substr(0, 8)))))
	{
		if (v.size() >= 8 && Csha1((boost::format("%s %d %d %s") % m_config.m_torrent_pass_private_key % user->torrent_pass_version % user->uid % info_hash).str()).read().substr(0, 12) == hex_decode(v.substr(8)))
			return user;
	}
	t_users_torrent_passes::const_iterator i = m_users_torrent_passes.find(v);
	return i == m_users_torrent_passes.end() ? NULL : i->second;
}

Cserver::t_user* Cserver::find_user_by_uid(int v)
{
	t_users::iterator i = m_users.find(v);
	return i == m_users.end() ? NULL : &i->second;
}

void Cserver::sig_handler(int v)
{
	switch (v)
	{
	case SIGTERM:
		g_sig_term = true;
		break;
	}
}

void Cserver::term()
{
	g_sig_term = true;
}

std::string Cserver::column_name(int v) const
{
	switch (v)
	{
	case column_files_completed:
		return m_config.m_column_files_completed;
	case column_files_leechers:
		return m_config.m_column_files_leechers;
	case column_files_seeders:
		return m_config.m_column_files_seeders;
	case column_files_fid:
		return m_config.m_column_files_fid;
	case column_users_uid:
		return m_config.m_column_users_uid;
	}
	assert(false);
	return "";
}

std::string Cserver::table_name(int v) const
{
	switch (v)
	{
	case table_announce_log:
		return m_config.m_table_announce_log.empty() ? m_table_prefix + "announce_log" : m_config.m_table_announce_log;
	case table_config:
		return m_table_prefix + "config";
	case table_deny_from_hosts:
		return m_config.m_table_deny_from_hosts.empty() ? m_table_prefix + "deny_from_hosts" : m_config.m_table_deny_from_hosts;
	case table_files:
		return m_config.m_table_files.empty() ? m_table_prefix + "files" : m_config.m_table_files;
	case table_files_users:
		return m_config.m_table_files_users.empty() ? m_table_prefix + "files_users" : m_config.m_table_files_users;
	case table_scrape_log:
		return m_config.m_table_scrape_log.empty() ? m_table_prefix + "scrape_log" : m_config.m_table_scrape_log;
	case table_users:
		return m_config.m_table_users.empty() ? m_table_prefix + "users" : m_config.m_table_users;
	case table_trackers:	//*_
		return m_config.m_table_trackers.empty() ? m_table_prefix + "trackers" : m_config.m_table_trackers;
	}
	assert(false);
	return "";
}

int Cserver::test_sql()
{
	if (!m_use_sql)
		return 0;
	try
	{
		mysql_get_server_version(&m_database.handle());
		if (m_config.m_log_announce)
			m_database.query("select id, ipa, port, event, info_hash, peer_id, downloaded, left0, uploaded, uid, mtime from " + table_name(table_announce_log) + " where 0");
		m_database.query("select name, value from " + table_name(table_config) + " where 0");
		m_database.query("select begin, end from " + table_name(table_deny_from_hosts) + " where 0");
		m_database.query("select " + column_name(column_files_fid) + ", info_hash, " + column_name(column_files_leechers) + ", " + column_name(column_files_seeders) + ", flags, mtime, ctime from " + table_name(table_files) + " where 0");
		m_database.query("select fid, uid, active, announced, completed, downloaded, `left`, uploaded from " + table_name(table_files_users) + " where 0");
		if (m_config.m_log_scrape)
			m_database.query("select id, ipa, info_hash, uid, mtime from " + table_name(table_scrape_log) + " where 0");
		m_database.query("select " + column_name(column_users_uid) + ", downloaded, uploaded from " + table_name(table_users) + " where 0");
		m_read_users_can_leech = m_database.query("show columns from " + table_name(table_users) + " like 'can_leech'");
		m_read_users_peers_limit = m_database.query("show columns from " + table_name(table_users) + " like 'peers_limit'");
		m_read_users_torrent_pass = m_database.query("show columns from " + table_name(table_users) + " like 'torrent_pass'");
		m_read_users_torrent_pass_version = true; // m_database.query("show columns from " + table_name(table_users) + " like 'torrent_pass_version'");
		m_read_users_torrents_limit = m_database.query("show columns from " + table_name(table_users) + " like 'torrents_limit'");
		m_read_users_wait_time = m_database.query("show columns from " + table_name(table_users) + " like 'wait_time'");
		return 0;
	}
	catch (Cdatabase::exception&)
	{
	}
	return 1;
}

