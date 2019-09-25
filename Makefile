REBAR=./rebar

all: src

src:
	$(REBAR) get-deps compile

clean:
	$(REBAR) clean

distclean: clean
	rm -f config.status
	rm -f config.log
	rm -rf autom4te.cache
	rm -rf deps
	rm -rf ebin
	rm -rf priv
	rm -f vars.config
	rm -f erl_crash.dump
	rm -f compile_commands.json
	rm -rf dialyzer

test: all
	$(REBAR) -v skip_deps=true eunit

xref: all
	$(REBAR) skip_deps=true xref

deps := $(wildcard deps/*/ebin)

dialyzer/erlang.plt:
	@mkdir -p dialyzer
	@dialyzer --build_plt --output_plt dialyzer/erlang.plt \
	-o dialyzer/erlang.log --apps kernel stdlib erts ssl \
	                              inets public_key crypto; \
	status=$$? ; if [ $$status -ne 2 ]; then exit $$status; else exit 0; fi

dialyzer/deps.plt:
	@mkdir -p dialyzer
	@dialyzer --build_plt --output_plt dialyzer/deps.plt \
	-o dialyzer/deps.log $(deps); \
	status=$$? ; if [ $$status -ne 2 ]; then exit $$status; else exit 0; fi

dialyzer/p1_acme.plt:
	@mkdir -p dialyzer
	@dialyzer --build_plt --output_plt dialyzer/p1_acme.plt \
	-o dialyzer/p1_acme.log ebin; \
	status=$$? ; if [ $$status -ne 2 ]; then exit $$status; else exit 0; fi

erlang_plt: dialyzer/erlang.plt
	@dialyzer --plt dialyzer/erlang.plt --check_plt -o dialyzer/erlang.log; \
	status=$$? ; if [ $$status -ne 2 ]; then exit $$status; else exit 0; fi

deps_plt: dialyzer/deps.plt
	@dialyzer --plt dialyzer/deps.plt --check_plt -o dialyzer/deps.log; \
	status=$$? ; if [ $$status -ne 2 ]; then exit $$status; else exit 0; fi

p1_acme_plt: dialyzer/p1_acme.plt
	@dialyzer --plt dialyzer/p1_acme.plt --check_plt -o dialyzer/p1_acme.log; \
	status=$$? ; if [ $$status -ne 2 ]; then exit $$status; else exit 0; fi

dialyzer: erlang_plt deps_plt p1_acme_plt
	@dialyzer --plts dialyzer/*.plt --no_check_plt \
	--get_warnings -Wunmatched_returns -o dialyzer/error.log ebin; \
	status=$$? ; if [ $$status -ne 2 ]; then exit $$status; else exit 0; fi

check-syntax:
	gcc -o nul -S ${CHK_SOURCES}

.PHONY: clean src test all dialyzer erlang_plt deps_plt p1_acme_plt
