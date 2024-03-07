spicy_add_analyzer(
    NAME STRRAT
    PACKAGE_NAME STRRAT
    SOURCES strrat.spicy strrat.evt zeek_strrat.spicy
    SCRIPTS __load__.zeek main.zeek dpd.sig
)
