#pragma once

#include <socket.h>

class Cserver;

/**
 * Client abstracting.
 */
class Cclient
{
public:
	virtual void process_events(int) = 0;	//!< Called when an EPOLL event occurs.
	virtual ~Cclient();
protected:
	const Csocket& s() const
	{
		return m_s;
	}

	void s(const Csocket& s)
	{
		m_s = s;
	}

	Csocket m_s;
	Cserver* m_server;
};
