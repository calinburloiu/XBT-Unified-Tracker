#pragma once

#include "client.h"

class Cserver;

/**
 * A handler for the listening socket which link with accept.
 */
class Ctcp_listen_socket: public Cclient
{
public:
	virtual void process_events(int);
	Cclient::s;
	Ctcp_listen_socket();
	Ctcp_listen_socket(Cserver*, const Csocket&);
};
