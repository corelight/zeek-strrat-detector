@load base/protocols/conn/removal-hooks

module STRRAT;

export {
	## Log stream identifier.
	redef enum Log::ID += { LOG };

	## The ports to register STRRAT for.
	const ports = {
		# TODO: Replace with actual port(s).
		12345/tcp,
	} &redef;

	## Record type containing the column fields of the STRRAT log.
	type Info: record {
		## Timestamp for when the activity happened.
		ts: time &log;
		## Unique ID for the connection.
		uid: string &log;
		## The connection's 4-tuple of endpoint addresses/ports.
		id: conn_id &log;

		# TODO: Adapt subsequent fields as needed.

		## Request-side payload.
		request: string &optional &log;
		## Response-side payload.
		reply: string &optional &log;
	};

	## A default logging policy hook for the stream.
	global log_policy: Log::PolicyHook;

	## Default hook into STRRAT logging.
	global log_strrat: event(rec: Info);

	## STRRAT finalization hook.
	global finalize_strrat: Conn::RemovalHook;
}

redef record connection += {
	strrat: Info &optional;
};

redef likely_server_ports += { ports };

event zeek_init() &priority=5
	{
	Log::create_stream(STRRAT::LOG, [$columns=Info, $ev=log_strrat, $path="strrat", $policy=log_policy]);

	Analyzer::register_for_ports(Analyzer::ANALYZER_STRRAT, ports);
	}

# Initialize logging state.
hook set_session(c: connection)
	{
	if ( c?$strrat )
		return;

	c$strrat = Info($ts=network_time(), $uid=c$uid, $id=c$id);
	Conn::register_removal_hook(c, finalize_strrat);
	}

function emit_log(c: connection)
	{
	if ( ! c?$strrat )
		return;

	Log::write(STRRAT::LOG, c$strrat);
	delete c$strrat;
	}

# Example event defined in strrat.evt.
event STRRAT::message(c: connection, is_orig: bool, payload: string)
	{
	hook set_session(c);

	local info = c$strrat;
	if ( is_orig )
		info$request = payload;
	else
		info$reply = payload;
	}

hook finalize_strrat(c: connection)
	{
	# TODO: For UDP protocols, you may want to do this after every request
	# and/or reply.
	emit_log(c);
	}
