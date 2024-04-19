# @TEST-DOC: Test Zeek parsing a trace file through the STRRAT analyzer.
#
# @TEST-EXEC: zeek -Cr ${TRACES}/strrat-4423258f-59bc-4a88-bfec-d8ac08c88538.pcap ${PACKAGE} %INPUT >output
# @TEST-EXEC: btest-diff output
# @TEST-EXEC: btest-diff notice.log
