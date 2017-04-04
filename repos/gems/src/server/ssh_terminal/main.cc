/*
 * \brief  Service providing the 'Terminal_session' interface via SSH
 * \author Norman Feske
 * \author Prashanth Mundkur
 * \date   2017-03-28
 */

/*
 * Copyright (C) 2011-2017 Genode Labs GmbH
 *
 * This file is part of the Genode OS framework, which is distributed
 * under the terms of the GNU Affero General Public License version 3.
 */

/* Genode includes */
#include <util/list.h>
#include <util/string.h>
#include <util/misc_math.h>
#include <base/log.h>
#include <base/rpc_server.h>
#include <base/heap.h>
#include <root/component.h>
#include <terminal_session/terminal_session.h>
#include <base/attached_ram_dataspace.h>
#include <os/session_policy.h>

#include <libc/component.h>
#include <pthread.h>

/* socket API */
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <poll.h>

/* libssh API */
#include <libssh/libssh.h>
#include <libssh/server.h>
#include <libssh/callbacks.h>

static bool const verbose = true;

enum { MAX_USER_LEN             = 63 + 1,
       MAX_PASSWORD_LEN         = 63 + 1,
       MAX_KEYS_FILENAME_LEN    = 63 + 1,
       MAX_AUTH_ATTEMPTS        = 3 };

/**
 * Structs for various libssh callbacks.
 */

struct channel_callback_data {
	/**
	 * Buffer for incoming data
	 *
	 * This buffer is used for synchronizing the reception of data
	 * in the main thread ('loop') and the entrypoint thread
	 * ('read_buffer'). The main thread fills the buffer if its not
	 * already occupied and the entrypoint thread consumes the
	 * buffer.
	 *
	 * If remote data arrives from libssh via the
	 * channel_data_callback while the buffer is occupied, it is
	 * not consumed, but left with libssh until the buffer
	 * empties.  Due to limitations in the libssh API, the channel
	 * cannot be disabled from further callbacks, resulting in the
	 * potential for busy callbacks until the buffer is drained.
	 */
	enum { READ_BUF_SIZE = 4096 };
	char           read_buf[READ_BUF_SIZE];
	Genode::size_t read_buf_bytes_used;
	Genode::size_t read_buf_bytes_read;

	/**
	 * Buffer for outgoing data
	 *
	 * This buffer is used for outgoing data, and is needed to
	 * prevent the entrypoint thread ('write') from accessing the
	 * libssh structures being used by the main thread
	 * ('watch_sockets_for_incoming_data').
	 *
	 * The entrypoint thread fills the buffer and the main thread
	 * consumes the buffer.  They protect against concurrent
	 * access using a lock.
	 *
	 * When the buffer is written to from the entrypoint thread,
	 * the connection gets put on a list; this list is monitored
	 * by the main thread, which drains the write buffers of the
	 * list members, and removes them from the list when the
	 * buffers are fully drained.
	 */
	enum { WRITE_BUF_SIZE = 4096 };
	char           write_buf[WRITE_BUF_SIZE];
	Genode::size_t write_buf_bytes_used;
	Genode::size_t write_buf_bytes_sent;
	Genode::Lock   write_lock;

	channel_callback_data()
	:
		read_buf_bytes_used(0),  read_buf_bytes_read(0),
		write_buf_bytes_used(0), write_buf_bytes_sent(0)
	{ }
};

struct session_callback_data
{
	/**
	 * Unsuccessful authentication attempts, reset to 0 when successful.
	 */
	int bad_auth_attempts;

	session_callback_data() : bad_auth_attempts(0)
	{ }
};

struct bind_callback_data
{
	int nsessions;
	int nerrors;

	bind_callback_data() : nsessions(0), nerrors(0)
	{ }
};

/**
 * Since there will only be a single active ssh session per ssh_bind
 * listener, and normally one channel per session, all the callback
 * data is aggregated into a single structure.
 *
 * Most of this structure contains libssh structs and is under the
 * control of the main thread which runs the libssh event loop; most
 * of it should not be accessed from the entry point thread.  The only
 * points of coordination accessible from both threads are the read
 * and write buffers, guarded by whether they are empty.
 */

struct callback_data
{
	/**
	 * callback_data is allocated by Ssh_conn in the entrythread, marked ACTIVE
	 * and attached to the event-loop.  When closing down, Ssh_conn requests the
	 * event-loop detach the callback_data by setting the state to DETACH.  The
	 * event-loop processes this detach request, and then marks it as DETACHED.
	 */
	enum { ACTIVE, DETACH, DETACHED } state;

	/**
	 * If libssh encounters any errors, it will be indicated by a
	 * value of SSH_ERROR in ssh_state; otherwise it is set to
	 * SSH_OK.  It is set by the main event-loop thread and read
	 * by Ssh_conn in the entrythread.
	 */
	int ssh_state;

	/**
	 * pointer fields allocated by libssh
	 */
	ssh_event   event_loop; /* the libssh poll-based event loop */
	ssh_bind    bind;       /* the accepting listener */
	ssh_session session;    /* the accepted ssh connection */
	ssh_channel channel;    /* the ssh data channel for the accepted connection */

	/**
	 * component-specific callback data
	 */
	struct bind_callback_data    bdata;
	struct session_callback_data sdata;
	struct channel_callback_data cdata;

	/**
	 * callback functions
	 */
	struct ssh_bind_callbacks_struct    bind_callbacks;
	struct ssh_server_callbacks_struct  session_callbacks;
	struct ssh_channel_callbacks_struct channel_callbacks;

	/**
	 * Signal handler to be informed about data available to read
	 */
	Genode::Signal_context_capability read_avail_sigh;

	/**
	 * Signal handler to be informed on an established connection
	 */
	Genode::Signal_context_capability connected_sigh;

	/**
	 * List element in pending registration list in event-loop
	 */
	Genode::List_element<callback_data> _pending_le;

	/**
	 * List element in active connection list in event-loop
	 */
	Genode::List_element<callback_data> _active_le;

	Genode::String<MAX_USER_LEN>     user;
	Genode::String<MAX_PASSWORD_LEN> password;

	/**
	 * The constructor runs in the entrypoint thread.
	 */
	callback_data(Genode::String<MAX_USER_LEN>     _user,
		      Genode::String<MAX_PASSWORD_LEN> _password)
	:
		state(ACTIVE), ssh_state(SSH_OK),
		event_loop(NULL), bind(NULL), session(NULL), channel(NULL),
		_pending_le(this), _active_le(this),
		user(_user), password(_password)
	{
		/*
		 * callback functions get initialized to their actual
		 * values when the incoming connection is set up.
		 */
		Genode::memset(&bind_callbacks,    0, sizeof(bind_callbacks));
		Genode::memset(&session_callbacks, 0, sizeof(session_callbacks));
		Genode::memset(&channel_callbacks, 0, sizeof(channel_callbacks));
	}

	/**
	 * The attacher and detacher run in the main thread.
	 */

	void attach_event_loop(ssh_event loop)
	{
		event_loop = loop;
		if (ssh_bind_listen(bind) < 0) {
			Genode::log(__func__, ": error on ssh listener: ",
				    ssh_get_error(bind));
			ssh_state = SSH_ERROR;
			return;
		}
		if (ssh_event_add_bind(event_loop, bind) != SSH_OK) {
			Genode::log(__func__, ": unable to add listener to event loop: ",
				    ssh_get_error(bind));
			ssh_state = SSH_ERROR;
		}
		Genode::log(__func__, ": attached to event loop");
	}

	void detach_event_loop()
	{
		if (channel) {
			ssh_channel_close(channel);
			ssh_channel_free(channel);
		}
		if (session) {
			ssh_disconnect(session);
			if (event_loop)
				ssh_event_remove_session(event_loop, session);
			close(ssh_get_fd(session));
			ssh_free(session);
		}
		if (bind) {
			if (event_loop)
				ssh_event_remove_bind(event_loop, bind);
			close(ssh_bind_get_fd(bind));
			ssh_bind_free(bind);
		}
		state = DETACHED;
		Genode::log(__func__, ": detached from event loop");
	}

	/**
	 * Return true if the internal read buffer is ready to receive data
	 */
	bool read_buffer_empty() const { return cdata.read_buf_bytes_used == 0; }

	/**
	 * Return true if the internal write buffer is fully drained
	 */
	bool send_buffer_empty() const { return cdata.write_buf_bytes_used == 0; }

	/**
	 * Drain the outgoing buffered data, and return the number of
	 * bytes remaining to be drained.  This is called from the
	 * main thread.
	 */
	Genode::size_t drain_buffer()
	{
		Genode::Lock(cdata.write_lock);

		int num_bytes = ssh_channel_write(channel,
						  cdata.write_buf + cdata.write_buf_bytes_sent,
						  cdata.write_buf_bytes_used - cdata.write_buf_bytes_sent);
		if (num_bytes < 0) return num_bytes;

		cdata.write_buf_bytes_sent += num_bytes;
		if (cdata.write_buf_bytes_sent >= cdata.write_buf_bytes_used) {
			cdata.write_buf_bytes_sent = 0;
			cdata.write_buf_bytes_used = 0;
			return 0;
		}
		return (cdata.write_buf_bytes_used - cdata.write_buf_bytes_sent);
	}

	/**************************************************************
	 * The below functions are called from the entrypoint thread. *
	 **************************************************************/

	/**
	 * Read out internal read buffer and copy into destination buffer.
	 */
	Genode::size_t read_buffer(char *dst, Genode::size_t dst_len)
	{
		if (cdata.read_buf_bytes_used == 0) return 0;

		Genode::size_t num_bytes = Genode::min(dst_len,
						       cdata.read_buf_bytes_used -
						       cdata.read_buf_bytes_read);
		Genode::memcpy(dst, cdata.read_buf + cdata.read_buf_bytes_read, num_bytes);
		cdata.read_buf_bytes_read += num_bytes;
		if (cdata.read_buf_bytes_read >= cdata.read_buf_bytes_used)
			cdata.read_buf_bytes_used = cdata.read_buf_bytes_read = 0;

		/* notify client if there are still bytes available for reading */
		if (read_avail_sigh.valid() && !read_buffer_empty())
			Genode::Signal_transmitter(read_avail_sigh).submit();

		return num_bytes;
	}

	/**
	 * Buffer data that needs to be sent by the main thread,
	 * and return the number of bytes buffered.
	 */
	Genode::size_t send_buffer(const char *src, Genode::size_t src_len)
	{
		Genode::Lock(cdata.write_lock);

		Genode::size_t num_bytes = Genode::min(src_len,
						       sizeof(cdata.write_buf) - cdata.write_buf_bytes_used);
		Genode::memcpy(cdata.write_buf + cdata.write_buf_bytes_used, src, num_bytes);
		cdata.write_buf_bytes_used += num_bytes;
		return num_bytes;
	}
 };

/**
 * Channel callbacks
 */

/**
 * Incoming data from the remote client on the channel, going to the
 * input of the terminal.
 */
static int channel_data_callback(ssh_session session, ssh_channel channel, void *data,
				 uint32_t len, int is_stderr, void *userdata)
{
	struct callback_data *d = reinterpret_cast<callback_data *>(userdata);
	struct channel_callback_data *cdata = &d->cdata;

	if (len == 0 || cdata->read_buf_bytes_used != 0) return 0;

	/*
	 * compute what fits into our buffer, and copy it in
	 */
	int bytes_used = Genode::min(len, sizeof(cdata->read_buf));
	Genode::memcpy(cdata->read_buf, (char *)data, bytes_used);
	cdata->read_buf_bytes_used += bytes_used;
	/*
	 * notify client about bytes available for reading
	 */
	if (d->read_avail_sigh.valid())
		Genode::Signal_transmitter(d->read_avail_sigh).submit();

	/*
	 * unfortunately libssh doesn't allow us to disable further
	 * data callbacks, resulting in the potential for busy
	 * callbacks from the event-loop.
	 */

	return bytes_used;
}

static void channel_eof_callback(ssh_session session, ssh_channel channel,
				 void *userdata)
{
	Genode::log(__func__);
}

static void channel_close_callback(ssh_session session, ssh_channel channel,
				   void *userdata)
{
	Genode::log(__func__);
}

static void channel_signal_callback(ssh_session session, ssh_channel channel,
				    const char *sig, void *userdata)
{
	Genode::log(__func__, ": ", sig);
}

static void channel_exit_status_callback(ssh_session session, ssh_channel channel,
					 int exit_status, void *userdata)
{
	Genode::log(__func__, ": ", exit_status);
}

static void channel_exit_signal_callback(ssh_session session, ssh_channel channel,
					 const char *signal, int core,
					 const char *errmsg, const char *lang,
					 void *userdata)
{
	Genode::log(__func__, ": ", signal, core, errmsg, lang);
}

static int channel_env_request_callback(ssh_session session, ssh_channel channel,
					const char *env_name, const char *env_value,
					void *userdata)
{
	Genode::log(__func__, ": env[", env_name, "] <-", env_value);
	return 0;
}

static int channel_shell_request_callback(ssh_session session, ssh_channel channel,
					  void *userdata)
{
	Genode::log(__func__);
	/* TODO: send connected signal? */
	return SSH_OK;
}

static int channel_exec_request_callback(ssh_session session, ssh_channel channel,
					 const char *command, void *userdata)
{
	Genode::log(__func__, ": ", command);
	return SSH_OK;
}

static int channel_subsystem_request_callback(ssh_session session, ssh_channel channel,
					      const char *subsystem, void *userdata)
{
	Genode::log(__func__, ": ", subsystem);
	return SSH_ERROR;
}

static int channel_pty_request_callback(ssh_session session, ssh_channel channel,
					const char *term,
					int cols, int rows, int py, int px,
					void *userdata)
{
	struct callback_data *d = reinterpret_cast<callback_data *>(userdata);

	if (d->connected_sigh.valid()) {
		Genode::log(__func__, ": connecting request for ", term);
		Genode::Signal_transmitter(d->connected_sigh).submit();
		return SSH_OK;
	}
	Genode::log(__func__, ": cannot connect request for ", term);
	return SSH_ERROR;
}

static int channel_pty_resize_callback(ssh_session session, ssh_channel channel,
				       int cols, int rows, int py, int px,
				       void *userdata)
{
	Genode::log(__func__);
	return SSH_ERROR;
}

/**
 * Session callbacks
 */

static int session_auth_password_callback(ssh_session session, const char *user,
					  const char *password, void *userdata)
{
	Genode::log(__func__);
	struct callback_data *d = reinterpret_cast<callback_data *>(userdata);

	if (strcmp(user, d->user.string()) == 0 &&
	    strcmp(password, d->password.string()) == 0)
	{
		d->sdata.bad_auth_attempts = 0;
		return SSH_AUTH_SUCCESS;
	}
	if (++d->sdata.bad_auth_attempts >= MAX_AUTH_ATTEMPTS) {
		Genode::log(__func__, ": too many authentication tries (%d) for user %s, disconnecting.",
			    d->sdata.bad_auth_attempts, user);
		ssh_disconnect(session);
	}
	return SSH_AUTH_DENIED;
}

static int session_service_request_callback(ssh_session session, const char *service,
					    void *userdata)
{
	Genode::log(__func__, ": ", service);
	if (strcmp(service, "ssh-userauth") == 0)
		return 0; /* allowed */
	return -1; /* not allowed */
}

static ssh_channel session_channel_open_callback(ssh_session session, void *userdata)
{
	Genode::log(__func__);
	struct callback_data *d = reinterpret_cast<callback_data *>(userdata);

	if (d->channel) {
		Genode::log(__func__, ": only one channel per session supported!");
		return NULL;
	}

	d->channel = ssh_channel_new(d->session);
	if (d->channel)
		ssh_set_channel_callbacks(d->channel, &d->channel_callbacks);

	return d->channel;
}

static void setup_incoming_connection(ssh_bind sshbind, void *userdata)
{
	Genode::log(__func__);
	struct callback_data *d = reinterpret_cast<callback_data *>(userdata);
	/* TODO: assert(d->session == NULL); */
	d->session = ssh_new();
	if (d->session == NULL) return;

	if (ssh_bind_accept(d->bind, d->session) == SSH_ERROR) {
		Genode::log(__func__, ": error accepting connection: ",
			    ssh_get_error(d->bind));
		return;
	}
	if (ssh_handle_key_exchange(d->session)) {
		Genode::log(__func__, ": error in handling key exchange: ",
			    ssh_get_error(d->session));
		return;
	}

	d->bdata.nsessions++;

	/*
	 * initialize the callbacks
	 */

	d->channel_callbacks.userdata = d;

	d->channel_callbacks.channel_pty_request_function = channel_pty_request_callback;
	d->channel_callbacks.channel_pty_window_change_function = channel_pty_resize_callback;
	d->channel_callbacks.channel_shell_request_function = channel_shell_request_callback;
	d->channel_callbacks.channel_env_request_function = channel_env_request_callback;
	d->channel_callbacks.channel_exec_request_function = channel_exec_request_callback;
	d->channel_callbacks.channel_subsystem_request_function = channel_subsystem_request_callback;

	d->channel_callbacks.channel_data_function = channel_data_callback;
	d->channel_callbacks.channel_eof_function = channel_eof_callback;
	d->channel_callbacks.channel_close_function = channel_close_callback;
	d->channel_callbacks.channel_signal_function = channel_signal_callback;

	d->channel_callbacks.channel_exit_status_function = channel_exit_status_callback;
	d->channel_callbacks.channel_exit_signal_function = channel_exit_signal_callback;

	ssh_callbacks_init(&d->channel_callbacks);

	d->session_callbacks.userdata = d;
	d->session_callbacks.auth_password_function = session_auth_password_callback;
	d->session_callbacks.service_request_function = session_service_request_callback;
	d->session_callbacks.channel_open_request_session_function = session_channel_open_callback;

	ssh_callbacks_init(&d->session_callbacks);

	ssh_set_server_callbacks(d->session, &d->session_callbacks);
	ssh_set_auth_methods(d->session, SSH_AUTH_METHOD_PASSWORD);

	/*
	 * we can now add this connection to the event loop
	 */
	ssh_event_add_session(d->event_loop, d->session);
}

/**
 *  This class is a thin wrapper around libssh structures contained in
 *  callback_data, and provides access to them from the entrythread,
 *  while the libssh structures are processed in the main thread.
 */
class Ssh_conn
{
	private:
		/**
		 * details about the ssh listener and any active ssh
		 * session
		 */
		struct callback_data conn;

	public:

		Ssh_conn(int                                    tcp_port,
			 Genode::String<MAX_USER_LEN>           user,
			 Genode::String<MAX_PASSWORD_LEN>       password,
			 Genode::String<MAX_KEYS_FILENAME_LEN>  dsa_key,
			 Genode::String<MAX_KEYS_FILENAME_LEN>  rsa_key);

		~Ssh_conn();

		/**************************************************************
		 * The below functions are called from the entrypoint thread. *
		 **************************************************************/

		/**
		 * Register signal handler to be notified once we accepted the TCP
		 * connection
		 */
		void connected_sigh(Genode::Signal_context_capability sigh)
		{
			conn.connected_sigh = sigh;
		}

		/**
		 * Register signal handler to be notified when data is available for
		 * reading
		 */
		void read_avail_sigh(Genode::Signal_context_capability sigh)
		{
			conn.read_avail_sigh = sigh;

			/* if read data is available right now, deliver signal immediately */
			if (!conn.read_buffer_empty() && conn.read_avail_sigh.valid())
				Genode::Signal_transmitter(conn.read_avail_sigh).submit();
		}

		/**
		 * Return true if the internal read buffer is ready to receive data
		 */
		bool read_buffer_empty() const { return conn.read_buffer_empty(); }

		/**
		 * Read out internal read buffer and copy into
		 * destination buffer.
		 */
		Genode::size_t read_buffer(char *dst, Genode::size_t dst_len)
		{
			return conn.read_buffer(dst, dst_len);
		}

		/**
		 * Write to internal send buffer if possible.
		 */
		Genode::size_t send_buffer(const char *src, Genode::size_t src_len)
		{
			return conn.send_buffer(src, src_len);
		}
};

class Ssh_conn_pool
{
	private:
		/**
		 * Protection for '_pending' list
		 */
		Genode::Lock _lock;

		/**
		 * List of pending conn registrations.  This is accessed from both
		 * threads, and is guarded by the above lock.
		 */
		Genode::List<Genode::List_element<callback_data> > _pending;

		/**
		 * List of active conns
		 */
		Genode::List<Genode::List_element<callback_data> > _active;

		/**
		 * Main thread, running the libssh event-loop
		 */
		pthread_t _libssh_thread;

		/**
		 * libssh event loop state
		 */
		ssh_event event_loop;

		/**
		 * Pipe used to synchronize the event-loop with the entrypoint thread
		 */
		int sync_pipe_fds[2];

		static int reset_wakeup_callback(socket_t fd, int revents, void *userdata)
		{
			int n = 0;
			if (revents & POLLIN) {
				char c;
				n = ::read(fd, &c, 1);
				Genode::log(__func__, ": processed a wakeup");
			}
			return n;
		}

		static void * entry(void *arg)
		{
			Ssh_conn_pool * pool = reinterpret_cast<Ssh_conn_pool *>(arg);
			for (;;)
				pool->loop();
			return nullptr;
		}

	public:
		Ssh_conn_pool(Genode::Env &env)
		{
			class Startup_event_loop_thread_failed : Genode::Exception { };

			Genode::log(__func__, ": starting event loop");

			ssh_init();

			event_loop = ssh_event_new();

			pipe(sync_pipe_fds);

			/*
			 * Add a handler for the read-side of the wakeup pipe
			 */
			if (ssh_event_add_fd(event_loop, sync_pipe_fds[0],
					     POLLIN, reset_wakeup_callback, NULL) != SSH_OK)
				throw Startup_event_loop_thread_failed();

			/*
			 * Start the main event loop thread
			 */
			if (pthread_create(&_libssh_thread, nullptr, entry, this))
				throw Startup_event_loop_thread_failed();
		}

		/**
		 * The following two functions are called from the entrythread context.
		 */

		void wakeup_event_loop()
		{
			char c = 0;
			::write(sync_pipe_fds[1], &c, sizeof(c));
		}

		void register_conn(callback_data *conn)
		{
			Genode::Lock(_lock);
			Genode::log(__func__, ": registering a connection request");
			_pending.insert(&conn->_pending_le);
			wakeup_event_loop();
		}

		/*
		 * This is the event loop running in the main thread context.
		 */
		void loop()
		{
			callback_data *conn;

			/*
			 * Process the active list: free detached conns, and drain
			 * the write buffers of the rest.  Do the latter so that the
			 * dopoll can actually do the socket writes needed for the
			 * draining.
			 */
			Genode::List_element<callback_data> *curr = _active.first(), *next = nullptr;
			for (; curr; curr = next) {
				conn = curr->object();
				switch (conn->state) {
				case callback_data::ACTIVE:
					if (!conn->send_buffer_empty())
						conn->drain_buffer();
					break;

				case callback_data::DETACH:
					Genode::log(__func__, ": detaching conn for user ", conn->user);
					next = curr->next();
					_active.remove(curr);
					conn->detach_event_loop();
					break;

				case callback_data::DETACHED:
					/* TODO: assert(false); */
					Genode::log(__func__, ": found Detached conn on Active list of user ", conn->user);
					break;
				}
			}

			/*
			 * Process pending registrations: move them to the
			 * active list and add them to the event loop.
			 */
			{
				Genode::Lock(_lock);

				curr = _pending.first();
				for (; curr; curr = next) {
					next = curr->next();
					_pending.remove(curr);

					conn = curr->object();
					Genode::log(__func__, ": attaching conn for user ", conn->user);

					_active.insert(&conn->_active_le);
					conn->attach_event_loop(event_loop);
				}
			}

			/**
			 * This is the place the main thread blocks; when poll
			 * returns, it does one round of the socket event processing,
			 * and goes back to the top of the loop.
			 */
			ssh_event_dopoll(event_loop, -1);
		}
};

Ssh_conn_pool *ssh_conn_pool(Genode::Env * env = nullptr)
{
	static Ssh_conn_pool inst(*env);
	return &inst;
}


Ssh_conn::Ssh_conn(int                                      tcp_port,
		   Genode::String<MAX_USER_LEN>             user,
		   Genode::String<MAX_PASSWORD_LEN>         password,
		   Genode::String<MAX_KEYS_FILENAME_LEN>    dsa_key,
		   Genode::String<MAX_KEYS_FILENAME_LEN>    rsa_key)
	: conn(user, password)
{
	conn.bind_callbacks.incoming_connection = setup_incoming_connection;
	ssh_callbacks_init(&conn.bind_callbacks);

	conn.bind = ssh_bind_new();
	ssh_bind_set_blocking(conn.bind, 0);
	ssh_bind_set_callbacks(conn.bind, &conn.bind_callbacks, &conn);

	ssh_bind_options_set(conn.bind, SSH_BIND_OPTIONS_BINDPORT, &tcp_port);
	ssh_bind_options_set(conn.bind, SSH_BIND_OPTIONS_DSAKEY, dsa_key.string());
	ssh_bind_options_set(conn.bind, SSH_BIND_OPTIONS_RSAKEY, rsa_key.string());

	ssh_conn_pool()->register_conn(&conn);
}

Ssh_conn::~Ssh_conn()
{
	/* Request a detach from the event loop. */
	conn.state = callback_data::DETACH;
	ssh_conn_pool()->wakeup_event_loop();

	/* Wait for the event-loop to detach us. */
	while (conn.state != callback_data::DETACHED)
		/* TODO: sleep?  use a timer (in a destructor?) */
		;
}


namespace Terminal {
	class Session_component;
	class Root_component;
};

class Terminal::Session_component : public Genode::Rpc_object<Session, Session_component>,
				    public Ssh_conn
{
	private:

		Genode::Attached_ram_dataspace _io_buffer;

	public:

		Session_component(Genode::Env &env, Genode::size_t io_buffer_size,
				  int                                   tcp_port,
				  Genode::String<MAX_USER_LEN>          user,
				  Genode::String<MAX_PASSWORD_LEN>      password,
				  Genode::String<MAX_KEYS_FILENAME_LEN> dsa_key,
				  Genode::String<MAX_KEYS_FILENAME_LEN> rsa_key)
		:
			Ssh_conn(tcp_port, user, password, dsa_key, rsa_key),
			_io_buffer(env.ram(), env.rm(), io_buffer_size)
		{
			Genode::log("created terminal session on port ", tcp_port);
		}

		/********************************
		 ** Terminal session interface **
		 ********************************/

		Size size() { return Size(0, 0); }

		bool avail()
		{
			return !read_buffer_empty();
		}

		Genode::size_t _read(Genode::size_t dst_len)
		{
			Genode::size_t num_bytes =
				read_buffer(_io_buffer.local_addr<char>(),
					    Genode::min(_io_buffer.size(), dst_len));

			return num_bytes;
		}

		Genode::size_t _write(Genode::size_t num_bytes)
		{
			/* sanitize argument */
			num_bytes = Genode::min(num_bytes, _io_buffer.size());

			/* write data to buffer */
			ssize_t written_bytes = send_buffer(_io_buffer.local_addr<char>(),
							    num_bytes);

			if (written_bytes < 0) {
				Genode::error("write error, dropping data");
				return 0;
			}

			return written_bytes;
		}

		Genode::Dataspace_capability _dataspace()
		{
			return _io_buffer.cap();
		}

		void read_avail_sigh(Genode::Signal_context_capability sigh)
		{
			Genode::log("setting read_avail_sigh on terminal session");
			Ssh_conn::read_avail_sigh(sigh);
		}

		void connected_sigh(Genode::Signal_context_capability sigh)
		{
			Genode::log("setting connected_sigh on terminal session");
			Ssh_conn::connected_sigh(sigh);
		}

		Genode::size_t read(void *buf, Genode::size_t) { return 0; }
		Genode::size_t write(void const *buf, Genode::size_t) { return 0; }
};


class Terminal::Root_component : public Genode::Root_component<Session_component>
{
	private:

		Genode::Env &_env;

	protected:

		Session_component *_create_session(const char *args)
		{
			using namespace Genode;

			/*
			 * XXX read I/O buffer size from args
			 */
			Genode::size_t io_buffer_size = 4096;

			try {
				Session_label const label = label_from_args(args);
				Session_policy policy(label);

				unsigned tcp_port = 0;
				Genode::String<MAX_USER_LEN>     user;
				Genode::String<MAX_PASSWORD_LEN> password;
				Genode::String<MAX_KEYS_FILENAME_LEN>  dsa_key;
				Genode::String<MAX_KEYS_FILENAME_LEN>  rsa_key;

				policy.attribute("port").value(&tcp_port);
				policy.attribute("user").value(&user);
				policy.attribute("password").value(&password);
				policy.attribute("dsa_key").value(&dsa_key);
				policy.attribute("rsa_key").value(&rsa_key);
				Genode::log(" creating session for <", args,
					    "> on port ", tcp_port,
					    " for user ", user);
				return new (md_alloc())
					Session_component(_env, io_buffer_size,
							  tcp_port, user, password,
							  dsa_key, rsa_key);

			} catch (Xml_node::Nonexistent_attribute) {
				error("Missing \"port\", \"user\", \"password\", \"dsa_key\", or \"rsa_key\" "
				      "attribute in policy definition");
				throw Root::Unavailable();
			} catch (Session_policy::No_policy_defined) {
				error("Invalid session request, no matching policy");
				throw Root::Unavailable();
			}
		}

	public:

		/**
		 * Constructor
		 */
		Root_component(Genode::Env &env, Genode::Allocator &md_alloc)
		:
			Genode::Root_component<Session_component>(&env.ep().rpc_ep(),
								  &md_alloc),
			_env(env)
		{ }
};


struct Main
{
	Genode::Env &_env;

	Genode::Sliced_heap _sliced_heap { _env.ram(), _env.rm() };

	/* create root interface for service */
	Terminal::Root_component _root { _env, _sliced_heap };

	Main(Genode::Env &env) : _env(env)
	{
		Genode::log("--- SSH terminal started ---");

		/* start thread blocking in select */
		ssh_conn_pool(&_env);

		/* announce service at our parent */
		Genode::log("--- announcing SSH terminal ---");
		_env.parent().announce(env.ep().manage(_root));

	}
};

void Libc::Component::construct(Libc::Env &env) { static Main main(env); }
