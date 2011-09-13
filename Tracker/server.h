#pragma once

#include "config.h"
#include "connection.h"
#include "epoll.h"
#include "stats.h"
#include "tcp_listen_socket.h"
#include "tracker_input.h"
#include "udp_listen_socket.h"
//#include "transaction.h"	//*_
#include <boost/array.hpp>
#include <boost/ptr_container/ptr_list.hpp>
#include <map>
#include <sql/database.h>
#include <xbt/virtual_binary.h>


class Ctransaction;

/**
 * Server functionality
 */
class Cserver
{
public:

	class peer_key_c;
	struct t_peer;
	struct t_file;
	typedef std::map<peer_key_c, t_peer> t_peers;

	/**
	 * Peer origin
	 */
	enum enum_peer_origin
	{
		PO_OWN = 0,		//!< Peers connected to this tracker
		PO_INTERNAL = 1,//!< Peers received from the "local tracker network"
		PO_EXTERNAL = 2,//!< Peers received from an "external tracker network"
	};

	/**
	 *_ Statuses of other trackers
	 */
	enum enum_conn_statuses
	{
		ST_DISCONNECTED = 0,

		ST_CONNECTED = 1,	//!< Opened connection
		ST_PENDING = 2,		//!< Recently disconnected or connected and sending SUMMARY
		ST_SYN = 4,			//!< SYN received, sending SYN_ACK until the connection is opened
		ST_SUMMARY = 8,		//!< SUMMARY received, sending UPDATE with flag summary until an UPDATE with flags summary and ack is received
		ST_UPDATING = 16,	//!< Sending update until confirmation
		ST_SEND_CANDIDATURE = 32,	//!< Sending my candidature
		ST_RECV_CANDIDATURE = 64,	//!< Receiving a tracker's candidature
		ST_SEND_LEADER = 128,		//!< Informing a tracker new in some swarm that I am the swarm leader

		ST_NO_UPDATE = ST_PENDING | ST_SEND_CANDIDATURE | ST_RECV_CANDIDATURE | ST_SEND_LEADER,
	};

	/**
	 *_ A host IP and a port which uniquely identifies as key a tracker in a map data structure.
	 */
	class tracker_key
	{
	public:
		tracker_key()
		{
			host = INADDR_NONE;
			port = -1;
		}

		tracker_key(in_addr_t host_, int port_)
		{
			host = host_;
			port = port_;
		}

		/**
		 * Implemented for ordered keys.
		 */
		bool operator<(tracker_key key) const
		{
			return host < key.host || host == key.host && port < key.port;
		}

		in_addr_t host;		//!< Tracker listening IP address
		int port;			//!< UDP port on the server
	};

	/**
	 *_ Information about a tracker.
	 */
	struct t_tracker
	{
		t_tracker();
		void clean_up_sent_peers();
		void clear()
		{
			update.clear();
			summary.clear();
			n_sent_dead_peers = 0;
		}

		// From DB
		int tid;				//!< TrackerID from the database table *_trackers
		char name[256];			//!< A human-friendly way to identify trackers
		in_addr_t host;			//!< Tracker listening IP address
		string str_host;		//!< Human readable host address (can be IP or URL)
		int port;				//!< UDP port on the server
		int nat_port;			//!< UDP port on the server if it uses NAT (-1 means no value)
		//char version[64];		//!< XBT Unified Tracker version
		char description[256];	//!< Information about the tracker (such as location, owner...)
		bool nat;				//!< True if the tracker uses NAT in which case nat_port is the destination port to the tracker
		bool external;			//!< A connection with a tracker from an external "tracker network"

		int status;				//!< Tracker status
		bool border_tracker;	//!< The tracker is a border tracker
		time_t recv_time;		//!< The time when the last packet was received from this tracker
		int retry_times;		//!< Number of times to retry sending a packet in a defined way
		int reconnect_time;
		bool delay;
		long long connection_id;//!< The virtual connection identifier
		int input_transaction_ids[5];	//!< The IDs for each input transaction, described in enum_transactions
		int output_transaction_ids[5];	//!< The IDs for each input transaction, described in enum_transactions
		int mandates;			//!< The number of swarm leader mandates this tracker has
		std::string update;		//!< An UPDATE packet payload
		std::string summary;	//!< A SUMMARY packet payload
		std::string leader;		//!< A LEADER packet payload
		t_peers::iterator sent_dead_peers[50];	//!< A list with the peers sent kept until their's UPDATE ACK
		int n_sent_dead_peers;
	};

	/**
	 * Peer identification by host (and uid)
	 */
	class peer_key_c
	{
	public:
		peer_key_c()
		{
		}

		peer_key_c(int host, int uid)
		{
			host_ = host;
#ifdef PEERS_KEY
			uid_ = uid;
#endif
		}

		bool operator<(peer_key_c v) const
		{
#ifdef PEERS_KEY
			return host_ < v.host_ || host_ == v.host_ && uid_ < v.uid_;
#else
			return host_ < v.host_;
#endif
		}

		int host_;
#ifdef PEERS_KEY
		int uid_;
#endif
	};

	/**
	 * Information about a peer
	 */
	struct t_peer
	{
		t_peer()
		{
			mtime = 0;

			origin = PO_OWN;
			dead = false;
			tracker = NULL;
			file = NULL;
		}

		long long downloaded;
		long long uploaded;
		time_t mtime;
		int uid;
		short port;
		bool left;
		boost::array<char, 20> peer_id;

		//*_ TSUP members:
		int origin;			//!< The source of the peer: PO_OWN, PO_INTERNAL or PO_EXTERNAL
		bool dead;			//!< True if the peer is no longer connected to the tracker, has been marked for deletion and must be sent in a future update
		t_tracker* tracker;	//!< Source tracker; NULL if origin is PO_OWN.
		t_file * file;		//!< The swarm where this peer is member.
	};

	//typedef std::map<peer_key_c, t_peer> t_peers;

	// ** See xbt_deny_from_hosts table
	struct t_deny_from_host
	{
		unsigned int begin;
		bool marked;
	};

	// ** See xbt_files table
	struct t_file
	{
		void clean_up(time_t t, Cserver&);
		void debug(std::ostream&) const;
		std::string select_peers(const Ctracker_input&) const;

		t_file()
		{
			completed = 0;
			dirty = true;
			fid = 0;
			leechers = 0;
			seeders = 0;

			b_swarm_leader = false;
			b_swarm_leader_ext = false;
			swarm_leader = NULL;
			swarm_leader_ext = NULL;
			new_arrivals = false;
		}

		t_peers peers;
		time_t ctime;
		int completed;
		int fid;
		int leechers;
		int seeders;
		bool dirty;

		//*_ TSUP members:
		std::set<t_tracker *> trackers;		//!< The list of trackers which unify on this swarm
		bool b_swarm_leader;				//!< Swarm has internal swarm leader
		bool b_swarm_leader_ext;			//!< Swarm has external swarm leader
		t_tracker *swarm_leader;			//!< The tracker responsible to send the updates to the other internal trackers from the swarm (NULL means I'm the one)
		t_tracker *swarm_leader_ext;		//!< The tracker responsible to send the updates to the other external trackers from the swarm (NULL means I'm the one)
		bool new_arrivals;
	};

	// ** See xbt_users table
	struct t_user
	{
		t_user()
		{
			can_leech = true;
			completes = 0;
			incompletes = 0;
			peers_limit = 0;
			torrent_pass_version = 0;
			torrents_limit = 0;
			wait_time = 0;
		}

		bool can_leech;
		bool marked;
		int uid;
		int completes;
		int incompletes;
		int peers_limit;
		int torrent_pass_version;
		int torrents_limit;
		int wait_time;
	};

	typedef std::map<std::string, t_file> t_files;
	typedef std::map<unsigned int, t_deny_from_host> t_deny_from_hosts;
	typedef std::map<int, t_user> t_users;
	typedef std::map<std::string, t_user*> t_users_torrent_passes;
	typedef std::map<tracker_key, t_tracker> t_trackers;				//!<_ A map of trackers (for TSUP).

	int test_sql(); //!< Verifies the DB and its integrity
	void accept(const Csocket&);
	t_user* find_user_by_torrent_pass(const std::string&, const std::string& info_hash);
	t_user* find_user_by_uid(int);
	void read_config(); //!< Reads the configuration from the DB (*_config table) and from the config file
	void write_db_files();
	void write_db_users();
	void read_db_deny_from_hosts();
	void read_db_files();
	void read_db_files_sql();
	void read_db_users();
	void read_db_trackers();
	void clean_up();
	std::string insert_peer(const Ctracker_input&, bool udp, t_user*);
	std::string debug(const Ctracker_input&) const;
	std::string statistics() const;
	Cvirtual_binary select_peers(const Ctracker_input&) const;
	Cvirtual_binary scrape(const Ctracker_input&);
	int run();
	static void term();
	Cserver(Cdatabase&, const std::string& table_prefix, bool use_sql, const std::string& conf_file);

	//*_ TSUP functions:
	void tsup_timers();
	void report_new_file(std::string info_hash);
	void report_delete_file(std::string info_hash);
	std::string get_info_hashes() const;
	void unify_swarm(std::string info_hash, t_tracker *tracker);
	void unify_swarms(std::string info_hashes, t_tracker *tracker);
	void update(const_memory_range updates, t_tracker *tracker);
	void append_update_peer(std::string& d, t_file& file, t_peers::iterator candidate);
	std::string build_update(t_files::iterator itFile, bool externalDest);
	void build_updates();
	std::string swarms_webpage() const;
	std::string trackers_webpage() const;
	void init_election_campaign(t_tracker *notifier);
	void choose_swarm_leaders();
	void new_border_tracker(t_tracker &tracker);

	const t_file* file(const std::string& id) const
	{
		t_files::const_iterator i = m_files.find(id);
		return i == m_files.end() ? NULL : &i->second;
	}

	/**
	 *_ Returns a tracker with a specified key, or NULL if it doesn't exist.
	 * Updates the recv_time of the tracker if b_update_time is true.
	 */
	t_tracker* tracker(in_addr_t host, int port)
	{
		t_trackers::iterator it;
		if ( (it = m_trackers.find(tracker_key(host, port))) != m_trackers.end() )
		{
			return &it->second;
		}

		return NULL;
	}

	const Cconfig& config() const
	{
		return m_config;
	}

	long long secret() const
	{
		return m_secret;
	}

	Cstats& stats()
	{
		return m_stats;
	}

	time_t time() const
	{
		return m_time;
	}

	int tsup_port() const
	{
		return m_tsup_port;
	}

	/*?void temp_summary(std::string s)
	{
		if(!s.compare(""))
			m_temp_summary.clear();
		else
			m_temp_summary = s;
	}*/

	void reset_hello_time()
	{
		m_hello_time = ::time(NULL);
	}

	void reset_update_time()
	{
		m_update_time = ::time(NULL);
	}

	bool generate_delay()
	{
		//return rand() % (m_config.m_max_delay_interval + 1);
		return rand() % 2;
	}

	bool election_campaign()
	{
		return m_election_campaign;
	}

	bool check_election_campaign_termination()
	{
		if(m_n_send_candidature <= 0 && m_n_recv_candidature <= 0)
		{
			m_election_campaign = false;
			return true;
		}
		return false;
	}

	void dec_n_send_candidature()
	{
		m_n_send_candidature--;
	}

	void dec_n_recv_candidature()
	{
		m_n_recv_candidature--;
	}

	int mandates()
	{
		return m_mandates;
	}

	bool border_tracker() const
	{
		return m_internal && m_external;
	}

	void set_swarm_leader(const std::string& id, t_tracker &tracker)
	{
		t_files::iterator i = m_files.find(id);
		if(i != m_files.end())
		{
			if(!tracker.external)
			{
				i->second.swarm_leader = &tracker;
				i->second.b_swarm_leader = true;
			}
			else
			{
				i->second.swarm_leader_ext = &tracker;
				i->second.b_swarm_leader_ext = true;
			}
		}
	}

	void start_election_campaign()
	{
		m_election_campaign = true;
		m_mandate_time = ::time(NULL);
	}

/*	t_trackers& trackers() const
	{
		return m_trackers;
	}*/

private:
	enum
	{
		column_files_completed,
		column_files_fid,
		column_files_leechers,
		column_files_seeders,
		column_users_uid,
		// ** DB table IDs
		table_announce_log,
		table_config,
		table_deny_from_hosts,
		table_files,
		table_files_users,
		table_scrape_log,
		table_users,
		table_trackers,		//*_
	};

	typedef boost::ptr_list<Cconnection> t_connections;
	typedef std::list<Ctcp_listen_socket> t_tcp_sockets;
	typedef std::list<Cudp_listen_socket> t_udp_sockets;

	int m_tsup_port;
	Csocket *m_tsup_socket;

	static void sig_handler(int v);
	std::string column_name(int v) const;
	std::string table_name(int) const; //!< Return the name of the table from the DB, based on its ID

	Cconfig m_config;
	Cstats m_stats;
	Ctransaction *m_transaction;	//*_
	bool m_read_users_can_leech;
	bool m_read_users_peers_limit;
	bool m_read_users_torrent_pass;
	bool m_read_users_torrent_pass_version;
	bool m_read_users_torrents_limit;
	bool m_read_users_wait_time;
	bool m_use_sql;

	time_t m_clean_up_time;
	time_t m_read_config_time;
	time_t m_read_db_deny_from_hosts_time;
	time_t m_read_db_files_time;
	time_t m_read_db_users_time;
	time_t m_time;		//!< Current time (updated in the server main loop).
	time_t m_write_db_files_time;
	time_t m_write_db_users_time;
	//*_ TSUP timers
	time_t m_hello_time;
	time_t m_update_time;
	time_t m_mandate_time;

	//*_ TSUP election process
	bool m_election_campaign;		//!< True if the election process is running
	int m_n_send_candidature;		//!< Number of trackers that have to receive my CANDIDATURE packets
	int m_n_recv_candidature;		//!< Number of trackers that have to send me CANDIDATURE packets
	int m_mandates;					//!< The number of swarm leader mandates this tracker has
	// TODO: future development: anticipated and local elections.
	//vector<t_files::iterator> m_anticipated_elections;	//!< A list of swarms where anticipated elections have to be done

	//*_ Variables that mark if a tracker is or not in an internal and an external network.
	bool m_internal;
	bool m_external;

	int m_fid_end;
	long long m_secret;
	t_connections m_connections;
	Cdatabase& m_database;
	Cepoll m_epoll;
	t_deny_from_hosts m_deny_from_hosts;
	t_files m_files;
	t_users m_users;
	t_users_torrent_passes m_users_torrent_passes;
	t_trackers m_trackers;		//!< The list of trackers (for TSUP).

	std::string m_announce_log_buffer;
	std::string m_conf_file;
	std::string m_files_users_updates_buffer;
	std::string m_scrape_log_buffer;
	std::string m_table_prefix;
	std::string m_users_updates_buffer;
	//*?std::string m_temp_summary;		//!<_ A temporary store of a SUMMARY packet payload for increasing performance on re-sending
};

void printStatus(Cserver::t_tracker &tracker);
