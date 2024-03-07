# @TEST-DOC: Test Zeek parsing a trace file through the STRRAT analyzer.
#
# @TEST-EXEC: zeek -Cr ${TRACES}/tcp-port-12345.pcap ${PACKAGE} %INPUT >output
# @TEST-EXEC: btest-diff output
# @TEST-EXEC: btest-diff strrat.log

# TODO: Adapt as suitable. The example only checks the output of the event
# handlers.

event STRRAT::message(c: connection, is_orig: bool, payload: string)
    {
    print fmt("Testing STRRAT: [%s] %s %s", (is_orig ? "request" : "reply"), c$id, payload);
    }
