@load base/protocols/conn/removal-hooks

module STRRAT;

export {
	## The notice when STRRAT C2 is observed.
	redef enum Notice::Type += { C2_Traffic_Observed };
}

# Example event defined in strrat.evt.
event STRRAT::message(c: connection, is_orig: bool, payload: string)
	{
	local msg = fmt("Potential STRRAT C2 between source %s and dest %s with is_orig %s and payload in the sub field.",
	    c$id$orig_h, c$id$resp_h, is_orig);

	NOTICE([ $note=STRRAT::C2_Traffic_Observed, $msg=msg, $sub=payload, $conn=c ]);
	}
