#pragma once

#include "client.h"

class Cserver;

/**
 * A handler for the listening UDP socket which links with the receiving function.
 */
class Cudp_listen_socket: public Cclient
{
public:
	virtual void process_events(int);
	Cclient::s;
	Cudp_listen_socket();
	Cudp_listen_socket(Cserver*, const Csocket&);
};
