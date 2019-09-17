%%%-------------------------------------------------------------------
%%% @author Evgeny Khramtsov <ekhramtsov@process-one.net>
%%% @copyright (C) 2002-2019 ProcessOne, SARL. All Rights Reserved.
%%%
%%% Licensed under the Apache License, Version 2.0 (the "License");
%%% you may not use this file except in compliance with the License.
%%% You may obtain a copy of the License at
%%%
%%%     http://www.apache.org/licenses/LICENSE-2.0
%%%
%%% Unless required by applicable law or agreed to in writing, software
%%% distributed under the License is distributed on an "AS IS" BASIS,
%%% WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
%%% See the License for the specific language governing permissions and
%%% limitations under the License.
%%%
%%%-------------------------------------------------------------------
-module(acme).

%% API
-export([start/0, stop/0]).
-export([issue/2, issue/3, issue/4]).
-export([revoke/3, revoke/4]).
-export([generate_key/1]).
-export([generate_csr/2]).
-export([format_error/1]).

-include_lib("public_key/include/public_key.hrl").

-define(DER_NULL, <<5, 0>>).
-define(DEFAULT_TIMEOUT, timer:minutes(1)).
-define(RETRY_TIMEOUT, 500).
-define(DEBUG(Fmt, Args),
	case State#state.debug_fun of
	    undefined -> ok;
	    _ -> (State#state.debug_fun)(Fmt, Args)
	end).

-record(state, {command        :: command(),
		dir_url        :: string(),
		domains        :: [binary()],
		contact        :: [binary()],
		end_time       :: integer(),
		challenge_type :: undefined | binary(),
		account        :: undefined | {priv_key(), undefined | string()},
		cert_type      :: undefined | cert_type(),
		cert           :: undefined | cert(),
		cert_key       :: undefined | priv_key(),
		ca_certs       :: [cert()],
		nonce          :: undefined | binary(),
		new_acc_url    :: undefined | string(),
		new_nonce_url  :: undefined | string(),
		new_order_url  :: undefined | string(),
		revoke_url     :: undefined | string(),
		order_url      :: undefined | string(),
		debug_fun      :: undefined | debug_fun(),
		challenge_fun  :: undefined | challenge_fun()}).

-type state() :: #state{}.
-type command() :: issue | revoke.
-type priv_key() :: public_key:private_key().
-type pub_key() :: #'RSAPublicKey'{} | #'ECPoint'{}.
-type cert() :: #'OTPCertificate'{}.
-type cert_type() :: ec | rsa.
-type challenge_data() :: [#{domain := binary(),
			     token := binary(),
			     key := binary()}].
-type challenge_fun() :: fun((challenge_data()) -> any()).
-type challenge_type() :: 'http-01'.
-type debug_fun() :: fun((string(), list()) -> _).
-type http_req_fun() :: fun((state()) -> {http_method(), _}).
-type option() :: {timeout, pos_integer()} |
		  {debug_fun, debug_fun()}.
-type issue_option() :: {contact, [binary() | string()]} |
			{cert_type, cert_type()} |
			{cert_key, priv_key()} |
			{ca_certs, [cert()]} |
			{challenge_type, challenge_type()} |
			{challenge_fun, challenge_fun()} |
			option().
-type revoke_option() :: option().
-type http_method() :: get | post | head.
-type http_header() :: {string(), string()}.
-type http_json() :: {100..699, [http_header()], map()}.
-type http_bin() :: {100..699, [http_header()], binary()}.
-type bad_cert_reason() :: cert_expired | invalid_issuer | invalid_signature |
			   name_not_permitted | missing_basic_constraint |
			   invalid_key_usage | selfsigned_peer | unknown_ca |
			   empty_chain | key_mismatch.
-type error_reason() :: {codec_error, yconf:error_reason(), yconf:ctx()} |
			{http_error, term()} |
			{challenge_failed, binary(), undefined | acme_codec:err_obj()} |
			{unsupported_challenges, binary(), [string()]} |
			{bad_pem, string()} |
			{bad_der, string()} |
			{bad_json, binary()} |
			{bad_cert, bad_cert_reason()} |
			{problem_report, acme_codec:err_obj()}.
-type error_return() :: {error, error_reason()}.
-type issue_return() :: {ok, #{acc_key := priv_key(),
			       cert_key := priv_key(),
			       cert_chain := [cert(), ...],
			       validation_result =>
				   valid | {bad_cert, bad_cert_reason()}}} |
			error_return().
-type revoke_return() :: ok | error_return().
-type acme_return() :: issue_return() | revoke_return().

-export_type([error_reason/0, issue_return/0, revoke_return/0, challenge_data/0]).

%%%===================================================================
%%% API
%%%===================================================================
start() ->
    case application:ensure_all_started(acme) of
	{ok, _} -> ok;
	Err -> Err
    end.

stop() ->
    application:stop(acme).

-spec issue(binary() | string(), [binary() | string()]) -> issue_return().
issue(DirURL, Domains) ->
    issue(DirURL, Domains, generate_key(ec), []).

-spec issue(binary() | string(), [binary() | string()],
	    priv_key() | [issue_option()]) -> issue_return().
issue(DirURL, Domains, Opts) when is_list(Opts) ->
    issue(DirURL, Domains, generate_key(ec), Opts);
issue(DirURL, Domains, AccKey) ->
    issue(DirURL, Domains, AccKey, []).

-spec issue(binary() | string(), [binary() | string()],
	    priv_key(), [issue_option()]) -> issue_return().
issue(DirURL, Domains, AccKey, Opts) ->
    State = init_state(issue, DirURL, Domains, AccKey, Opts),
    request_directory(State).

-spec revoke(binary() | string(), cert(), priv_key()) -> revoke_return().
revoke(DirURL, Cert, CertKey) ->
    revoke(DirURL, Cert, CertKey, []).

-spec revoke(binary() | string(), cert(), priv_key(), [revoke_option()]) -> revoke_return().
revoke(DirURL, Cert, CertKey, Opts) ->
    State = init_state(revoke, DirURL, Cert, CertKey, Opts),
    request_directory(State).

-spec format_error(error_reason()) -> string().
format_error({codec_error, Reason, Ctx}) ->
    format("Invalid JSON object: ~s", [yconf:format_error(Reason, Ctx)]);
format_error({http_error, Err}) ->
    "HTTP error: " ++
	case Err of
	    {code, Code, ""} ->
		integer_to_list(Code);
	    {code, Code, Slogan} ->
		format("~s (~B)", [Slogan, Code]);
	    {failed_connect, Reason} when is_atom(Reason) ->
		format_inet_error(Reason);
	    socket_closed_remotely ->
		format_inet_error(econnreset);
	    {could_not_parse_as_http, _} ->
		"received malformed HTTP packet";
	    {missing_header, Header} ->
		format("missing '~s' header", [Header]);
	    {unexpected_content_type, Type} ->
		format("unexpected content type: ~s", [Type]);
	    _ ->
		format("~p", [Err])
	end;
format_error({challenge_failed, Domain, undefined}) ->
    format("Challenge failed for domain ~s", [Domain]);
format_error({challenge_failed, Domain, ErrObj}) ->
    format("Challenge failed for domain ~s: ~s",
	   [Domain, format_problem_report(ErrObj)]);
format_error({unsupported_challenges, Domain, Types}) ->
    format("ACME server offered unsupported challenges for domain ~s: ~s",
	   [Domain, string:join(Types, ", ")]);
format_error({bad_pem, URL}) ->
    format("Failed to decode PEM certificate chain obtained from ~s", [URL]);
format_error({bad_der, URL}) ->
    format("Failed to decode ASN.1 DER certificate in the chain obtained from ~s", [URL]);
format_error({bad_json, Data}) ->
    format("Failed to decode JSON object: ~s", [Data]);
format_error({bad_cert, Reason}) ->
    format_bad_cert_error(Reason);
format_error({problem_report, ErrObj}) ->
    format_problem_report(ErrObj);
format_error(Other) ->
    format("Unrecognized error: ~p", [Other]).

-spec format_bad_cert_error(bad_cert_reason()) -> string().
format_bad_cert_error(empty_chain) ->
    "certificate chain is empty";
format_bad_cert_error(key_mismatch) ->
    "certificate's public key doesn't match local private key";
format_bad_cert_error(cert_expired) ->
    "certificate in the chain is no longer valid as its expiration date has passed";
format_bad_cert_error(invalid_issuer) ->
    "certificate issuer name does not match the name of the "
    "issuer certificate";
format_bad_cert_error(invalid_signature) ->
    "certificate in the chain was not signed by its issuer certificate";
format_bad_cert_error(name_not_permitted) ->
    "invalid Subject Alternative Name extension";
format_bad_cert_error(missing_basic_constraint) ->
    "certificate, required to have the basic constraints extension, "
    "does not have a basic constraints extension";
format_bad_cert_error(invalid_key_usage) ->
    "certificate key is used in an invalid way according "
    "to the key-usage extension";
format_bad_cert_error(selfsigned_peer) ->
    "self-signed certificate in the chain";
format_bad_cert_error(unknown_ca) ->
    "certificate chain is signed by unknown CA".

-spec format_inet_error(atom()) -> string().
format_inet_error(Reason) when is_atom(Reason) ->
    case inet:format_error(Reason) of
        "unknown POSIX error" -> atom_to_list(Reason);
        Txt -> Txt
    end.

-spec format_problem_report(acme_codec:err_obj()) -> string().
format_problem_report(#{type := Type, detail := Detail}) ->
    format("ACME server reported: ~s (error type: ~s)", [Detail, Type]);
format_problem_report(#{type := Type}) ->
    format("ACME server responded with ~s error", [Type]).

-spec format(string(), list()) -> list().
format(Fmt, Args) ->
    lists:flatten(io_lib:format(Fmt, Args)).

%%%===================================================================
%%% Internal functions
%%%===================================================================
%%%===================================================================
%%% ACME Requests
%%%===================================================================
-spec request_directory(state()) -> acme_return().
request_directory(State) ->
    Req = fun(S) ->
		  {get, {S#state.dir_url, []}}
	  end,
    case http_request(State, Req) of
	{ok, Reply, State1} ->
	    handle_directory_response(Reply, State1);
	Err ->
	    Err
    end.

-spec request_new_nonce(state()) -> acme_return().
request_new_nonce(State) ->
    Req = fun(S) ->
		  {head, {S#state.new_nonce_url, []}}
	  end,
    case http_request(State, Req) of
	{ok, Reply, State1} ->
	    handle_nonce_response(Reply, State1);
	Err ->
	    Err
    end.

-spec request_new_account(state()) -> issue_return().
request_new_account(State) ->
    Req = fun(S) ->
		  Body = #{<<"termsOfServiceAgreed">> => true,
			   <<"contact">> => S#state.contact},
		  JoseJSON = jose_json(S, Body, S#state.new_acc_url),
		  {post, {S#state.new_acc_url, [],
			  "application/jose+json", JoseJSON}}
	  end,
    case http_request(State, Req) of
	{ok, Reply, State1} ->
	    handle_account_response(Reply, State1);
	Err ->
	    Err
    end.

-spec request_new_order(state()) -> issue_return().
request_new_order(State) ->
    Req = fun(S) ->
		  Body = #{<<"identifiers">> =>
			       [#{<<"type">> => <<"dns">>,
				  <<"value">> => Domain}
				|| Domain <- S#state.domains]},
		  JoseJSON = jose_json(S, Body, S#state.new_order_url),
		  {post, {S#state.new_order_url, [],
			  "application/jose+json", JoseJSON}}
	  end,
    case http_request(State, Req) of
	{ok, Reply, State1} ->
	    handle_order_response(Reply, State1);
	Err ->
	    Err
    end.

-spec request_domain_auth(state(), [string()]) ->
				 {ok, state(), [{binary(), acme_codec:challenge_obj()}]} |
				 error_return().
request_domain_auth(State, AuthURLs) ->
    request_domain_auth(State, AuthURLs, []).

-spec request_domain_auth(state(), [string()],
			  [{binary(), acme_codec:challenge_obj()}]) ->
				 {ok, state(), [{binary(), acme_codec:challenge_obj()}]} |
				 error_return().
request_domain_auth(State, [URL|URLs], Challenges) ->
    Req = fun(S) ->
		  JoseJSON = jose_json(S, <<>>, URL),
		  {post, {URL, [], "application/jose+json", JoseJSON}}
	  end,
    case http_request(State, Req) of
	{ok, Reply, State1} ->
	    case handle_domain_auth_response(Reply, State1) of
		{ok, Challenge} ->
		    request_domain_auth(State1, URLs, [Challenge|Challenges]);
		Err ->
		    Err
	    end;
	Err ->
	    Err
    end;
request_domain_auth(State, [], Challenges) ->
    {ok, State, Challenges}.

-spec request_challenges(state(), [{binary(), acme_codec:challenge_obj()}]) -> issue_return().
request_challenges(State, Challenges) ->
    {Pending, _InProgress, _Valid, Invalid} = split_challenges(Challenges),
    case Invalid of
	[{Domain, Challenge}|_] ->
	    Reason = maps:get(error, Challenge, undefined),
	    mk_error({challenge_failed, Domain, Reason});
	[] ->
	    case Pending of
		[_|_] ->
		    Args = lists:map(
			     fun({Domain, #{token := Token}}) ->
				     #{domain => Domain,
				       key => auth_key(State, Token),
				       token => Token}
			     end, Pending),
		    (State#state.challenge_fun)(Args);
		[] ->
		    ok
	    end,
	    case lists:foldl(
		   fun(_, {error, _} = Err) ->
			   Err;
		      ({_, C}, S) ->
			   request_challenge(S, C)
		   end, State, Pending) of
		{error, Reason} -> {error, Reason};
		State1 -> poll(State1)
	    end
    end.

-spec request_challenge(state(), acme_codec:challenge_obj()) -> state() | error_return().
request_challenge(State, #{url := URL0}) ->
    URL = binary_to_list(URL0),
    Req = fun(S) ->
		  JoseJSON = jose_json(S, #{}, URL),
		  {post, {URL, [], "application/jose+json", JoseJSON}}
	  end,
    case http_request(State, Req) of
	{ok, _Reply, State1} ->
	    State1;
	Err ->
	    Err
    end.

-spec request_certificate(state(), string()) -> issue_return().
request_certificate(State, URL) ->
    {DerCSR, State1} = generate_csr(State),
    Body = #{<<"csr">> => base64url:encode(DerCSR)},
    Req = fun(S) ->
		  JoseJSON = jose_json(S, Body, URL),
		  {post, {URL, [], "application/jose+json", JoseJSON}}
	  end,
    case http_request(State1, Req) of
	{ok, Reply, State2} ->
	    handle_order_response(Reply, State2);
	Err ->
	    Err
    end.

-spec revoke_certificate(state()) -> revoke_return().
revoke_certificate(#state{revoke_url = URL,
			  cert_key = CertKey,
			  cert = Cert} = State) ->
    DerCert = public_key:pkix_encode('OTPCertificate', Cert, otp),
    Body = #{<<"certificate">> => base64url:encode(DerCert)},
    State1 = State#state{account = {CertKey, undefined}},
    Req = fun(S) ->
		  JoseJSON = jose_json(S, Body, URL),
		  {post, {URL, [], "application/jose+json", JoseJSON}}
	  end,
    case http_request(State1, Req) of
	{ok, _, _} ->
	    ok;
	Err ->
	    Err
    end.

-spec request_pem_file(state(), string()) -> issue_return().
request_pem_file(State, URL) ->
    Req = fun(S) ->
		  JoseJSON = jose_json(S, <<>>, URL),
		  {post, {URL, [], "application/jose+json", JoseJSON}}
	  end,
    case http_request(State, Req) of
	{ok, Reply, State1} ->
	    handle_pem_file_response(Reply, URL, State1);
	Err ->
	    Err
    end.

-spec poll(state()) -> issue_return().
poll(State) ->
    poll(State, ?RETRY_TIMEOUT).

-spec poll(state(), non_neg_integer()) -> issue_return().
poll(#state{order_url = URL} = State, Timeout) ->
    Req = fun(S) ->
		  JoseJSON = jose_json(S, <<>>, URL),
		  {post, {URL, [], "application/jose+json", JoseJSON}}
	  end,
    case http_request(State, Req) of
	{ok, Reply, State1} ->
	    handle_poll_response(Reply, State1, Timeout);
	Err ->
	    Err
    end.

%%%===================================================================
%%% Response processing
%%%===================================================================
-spec handle_directory_response(http_json(), state()) -> acme_return().
handle_directory_response({_, _Hdrs, JSON}, State) ->
    case acme_codec:decode_dir_obj(JSON) of
	{ok, #{newNonce := NonceURL,
	       newAccount := AccURL,
	       newOrder := OrderURL,
	       revokeCert := RevokeURL}} ->
	    State1 = State#state{new_nonce_url = binary_to_list(NonceURL),
				 new_acc_url = binary_to_list(AccURL),
				 new_order_url = binary_to_list(OrderURL),
				 revoke_url = binary_to_list(RevokeURL)},
	    request_new_nonce(State1);
	Err ->
	    mk_codec_error(Err)
    end.

-spec handle_nonce_response(http_json(), state()) -> acme_return().
handle_nonce_response({_, Hdrs, _}, State) ->
    case lists:keyfind("replay-nonce", 1, Hdrs) of
	{_, Nonce} ->
	    State1 = State#state{nonce = iolist_to_binary(Nonce)},
	    case State1#state.command of
		issue -> request_new_account(State1);
		revoke -> revoke_certificate(State1)
	    end;
	false ->
	    mk_http_error({missing_header, 'Replay-Nonce'})
    end.

-spec handle_account_response(http_json(), state()) -> issue_return().
handle_account_response({_, Hdrs, JSON}, State) ->
    case find_location(Hdrs) of
	undefined ->
	    mk_http_error({missing_header, 'Location'});
	AccURL ->
	    case acme_codec:decode_acc_obj(JSON) of
		{ok, _} ->
		    {AccKey, _} = State#state.account,
		    State1 = State#state{account = {AccKey, AccURL}},
		    request_new_order(State1);
		Err ->
		    mk_codec_error(Err)
	    end
    end.

-spec handle_order_response(http_json(), state()) -> issue_return().
handle_order_response({_, Hdrs, JSON}, State) ->
    case find_location(Hdrs, State#state.order_url) of
	undefined ->
	    mk_http_error({missing_header, 'Location'});
	OrderURL ->
	    case acme_codec:decode_order_obj(JSON) of
		{ok, #{status := ready,
		       finalize := FinURL}} ->
		    request_certificate(State, binary_to_list(FinURL));
		{ok, #{status := valid,
		       certificate := CertURL}} ->
		    request_pem_file(State, binary_to_list(CertURL));
		{ok, #{authorizations := AuthURLs}} ->
		    State1 = State#state{order_url = OrderURL},
		    case request_domain_auth(
			   State1, lists:map(fun binary_to_list/1, AuthURLs)) of
			{ok, State2, Challenges} ->
			    request_challenges(State2, Challenges);
			Err ->
			    Err
		    end;
		Err ->
		    mk_codec_error(Err)
	    end
    end.

-spec handle_domain_auth_response(http_json(), state()) ->
					 {ok, {binary(), acme_codec:challenge_obj()}} |
					 error_return().
handle_domain_auth_response({_, _Hdrs, JSON}, State) ->
    case acme_codec:decode_auth_obj(JSON) of
	{ok, #{challenges := Challenges,
	       identifier := #{value := D}}} ->
	    case lists:dropwhile(
		   fun(#{type := T}) ->
			   T /= State#state.challenge_type
		   end, Challenges) of
		[Challenge|_] -> {ok, {D, Challenge}};
		[] ->
		    Types = [binary_to_list(maps:get(type, C))
			     || C <- Challenges],
		    mk_error({unsupported_challenges, D, Types})
	    end;
	Err ->
	    mk_codec_error(Err)
    end.

-spec handle_poll_response(http_json(), state(), non_neg_integer()) -> issue_return().
handle_poll_response({_, _, JSON} = Response, State, Timeout) ->
    case acme_codec:decode_order_obj(JSON) of
	{ok, #{status := Status}} when Status == pending;
				       Status == processing ->
	    Timeout1 = min(Timeout, get_timeout(State)),
	    timer:sleep(Timeout1),
	    poll(State, Timeout1*2);
	{ok, _} ->
	    handle_order_response(Response, State);
	Err ->
	    mk_codec_error(Err)
    end.

-spec handle_pem_file_response(http_bin(), string(), state()) -> issue_return().
handle_pem_file_response({_, _, CertPEM}, URL,
			 #state{cert_key = CertKey,
				ca_certs = CaCerts,
				account = {AccKey, _}}) ->
    try lists:map(
	  fun({'Certificate', DER, not_encrypted}) -> DER end,
	  public_key:pem_decode(CertPEM)) of
	DERs ->
	    try lists:map(
		  fun(DER) ->
			  public_key:pkix_decode_cert(DER, otp)
		  end, DERs) of
		[] ->
		    mk_error({bad_cert, empty_chain});
		CertChain ->
		    Ret = #{acc_key => AccKey,
			    cert_key => CertKey,
			    cert_chain => CertChain},
		    Ret1 = case CaCerts of
			       [] -> Ret;
			       _ ->
				   Ret#{validation_result =>
					    validate_cert_chain(
					      CertChain, DERs, CertKey, CaCerts)}
			   end,
		    {ok, Ret1}
	    catch _:_ ->
		    mk_error({bad_der, URL})
	    end
    catch _:_ ->
	    mk_error({bad_pem, URL})
    end.

%%%===================================================================
%%% HTTP request
%%%===================================================================
-spec http_request(state(), http_req_fun()) ->
			  {ok, http_json() | http_bin(), state()} | error_return().
http_request(State, ReqFun) ->
    http_request(State, ReqFun, ?RETRY_TIMEOUT).

-spec http_request(state(), http_req_fun(), non_neg_integer()) ->
			  {ok, http_json() | http_bin(), state()} | error_return().
http_request(State, ReqFun, RetryTimeout) ->
    case get_timeout(State) of
	0 ->
	    mk_http_error(etimedout);
	Timeout ->
	    {Method, URL} = Request = ReqFun(State),
	    ?DEBUG("HTTP request: ~p", [Request]),
	    case httpc:request(Method, URL,
			       [{timeout, infinity},
				{connect_timeout, infinity}],
			       [{body_format, binary},
				{sync, false}]) of
		{ok, Ref} ->
		    ReqTimeout = min(timer:seconds(10), Timeout),
		    receive
			{http, {Ref, Response}} ->
			    ?DEBUG("HTTP response: ~p", [Response]),
			    handle_http_response(
			      ReqFun, Response, State, RetryTimeout)
		    after ReqTimeout ->
			    ?DEBUG("HTTP request timeout", []),
			    httpc:cancel_request(Ref),
			    http_request(State, ReqFun, RetryTimeout)
		    end;
		{error, WTF} ->
		    mk_http_error(WTF)
	    end
    end.

-spec http_retry(state(), http_req_fun(), non_neg_integer(), error_reason()) ->
			{ok, http_json() | http_bin(), state()} | error_return().
http_retry(State, ReqFun, RetryTimeout, Reason) ->
    case {need_retry(Reason), get_timeout(State)} of
	{true, Timeout} when Timeout > RetryTimeout ->
	    timer:sleep(RetryTimeout),
	    http_request(State, ReqFun, RetryTimeout*2);
	_ ->
	    mk_error(Reason)
    end.

-spec need_retry(error_reason()) -> boolean().
need_retry({http_error, {failed_connect, Reason}}) ->
    case Reason of
	ehostdown -> true;
	ehostunreach -> true;
	enetdown -> true;
	enetreset -> true;
	enetunreach -> true;
	etimedout -> true;
	erefused -> true;
	econnrefused -> true;
	econnreset -> true;
	_ -> false
    end;
need_retry({http_error, socket_closed_remotely}) -> true;
need_retry({http_error, {code, Code, _}}) when Code >= 500, Code < 600 -> true;
need_retry({problem_report, #{type := Type}})
  when Type == badNonce; Type == serverInternal ->
    true;
need_retry({problem_report, #{status := Code}})
  when Code >= 500, Code < 600 ->
    true;
need_retry(_) -> false.

%%%===================================================================
%%% HTTP response processing
%%%===================================================================
-spec handle_http_response(http_req_fun(),
			   {{_, 100..699, string()}, [http_header()], binary()} | term(),
			   state(), non_neg_integer()) ->
				  {ok, http_json() | http_bin(), state()} | error_return().
handle_http_response(ReqFun, {{_, Code, Slogan}, Hdrs, Body}, State, RetryTimeout) ->
    case lists:keyfind("content-type", 1, Hdrs) of
	{_, Type} when Type == "application/problem+json";
		       Type == "application/json" ->
	    State1 = update_nonce(Hdrs, State),
	    try jiffy:decode(Body, [return_maps]) of
		JSON when Type == "application/json" ->
		    {ok, {Code, Hdrs, JSON}, State1};
		JSON when Type == "application/problem+json" ->
		    case acme_codec:decode_err_obj(JSON) of
			{ok, ErrObj} ->
			    http_retry(State1, ReqFun, RetryTimeout,
				       {problem_report, ErrObj});
			Err ->
			    mk_codec_error(Err)
		    end
	    catch _:_ ->
		    mk_error({bad_json, Body})
	    end;
	{_, Type} when Code >= 200, Code < 300 ->
	    case Type of
		"application/pem-certificate-chain" ->
		    {ok, {Code, Hdrs, Body}, State};
		_ ->
		    mk_http_error({unexpected_content_type, Type})
	    end;
	false when Code >= 200, Code < 300 ->
	    case Body of
		<<>> ->
		    {ok, {Code, Hdrs, #{}}, State};
		_ ->
		    mk_http_error({missing_header, 'Content-Type'})
	    end;
	_ when Code >= 500, Code < 600 ->
	    http_retry(State, ReqFun, RetryTimeout,
		       prep_http_error({code, Code, Slogan}));
	_ ->
	    mk_http_error({code, Code, Slogan})
    end;
handle_http_response(ReqFun, {error, Reason}, State, RetryTimeout) ->
    http_retry(State, ReqFun, RetryTimeout, prep_http_error(Reason));
handle_http_response(ReqFun, Term, State, RetryTimeout) ->
    http_retry(State, ReqFun, RetryTimeout, prep_http_error(Term)).

prep_http_error({failed_connect, List} = Reason) when is_list(List) ->
    {http_error,
     case lists:keyfind(inet, 1, List) of
	 {_, _, Why} ->
	     {failed_connect,
	      case Why of
		  timeout -> etimedout;
		  closed -> econnrefused;
		  _ -> Why
	      end};
	 _ ->
	     Reason
     end};
prep_http_error(Reason) ->
    {http_error, Reason}.

-spec update_nonce([http_header()], state()) -> state().
update_nonce(Hdrs, State) ->
    case lists:keyfind("replay-nonce", 1, Hdrs) of
	{_, Nonce} ->
	    State#state{nonce = iolist_to_binary(Nonce)};
	false ->
	    State
    end.

%%%===================================================================
%%% Crypto stuff
%%%===================================================================
-spec generate_key(cert_type()) -> priv_key().
generate_key(ec) ->
    public_key:generate_key({namedCurve, secp256r1});
generate_key(rsa) ->
    public_key:generate_key({rsa, 2048, 65537}).

-spec generate_csr([binary(), ...], priv_key()) -> #'CertificationRequest'{}.
generate_csr([_|_] = Domains, PrivKey) ->
    SignAlgoOID = signature_algorithm(PrivKey),
    PubKey = pubkey_from_privkey(PrivKey),
    {DigestType, _} = public_key:pkix_sign_types(SignAlgoOID),
    DerParams = der_params(PrivKey),
    DerSAN = public_key:der_encode(
	       'SubjectAltName',
	       [{dNSName, binary_to_list(Domain)} || Domain <- Domains]),
    Extns = [#'Extension'{extnID = ?'id-ce-subjectAltName',
			  critical = false,
			  extnValue = DerSAN}],
    DerExtnReq = public_key:der_encode('ExtensionRequest', Extns),
    Attribute = #'AttributePKCS-10'{type = ?'pkcs-9-at-extensionRequest',
				    values = [{asn1_OPENTYPE, DerExtnReq}]},
    SubjPKInfo = #'CertificationRequestInfo_subjectPKInfo'{
		    subjectPublicKey = subject_pubkey(PubKey),
		    algorithm =
			#'CertificationRequestInfo_subjectPKInfo_algorithm'{
			   algorithm = algorithm(PrivKey),
			   parameters = {asn1_OPENTYPE, DerParams}}},
    CsrInfo = #'CertificationRequestInfo'{
		 version = v1,
		 subject = {rdnSequence, []},
		 subjectPKInfo = SubjPKInfo,
		 attributes = [Attribute]},
    DerCsrInfo = public_key:der_encode('CertificationRequestInfo', CsrInfo),
    Signature = public_key:sign(DerCsrInfo, DigestType, PrivKey),
    #'CertificationRequest'{
       certificationRequestInfo = CsrInfo,
       signatureAlgorithm =
	   #'CertificationRequest_signatureAlgorithm'{
	      algorithm = SignAlgoOID},
       signature = Signature}.

-spec generate_csr(state()) -> {binary(), state()}.
generate_csr(#state{domains = Domains,
		    cert_type = Type,
		    cert_key = Key} = State) ->
    CertKey = case Key of
		  undefined -> generate_key(Type);
		  _ -> Key
	      end,
    CSR = generate_csr(Domains, CertKey),
    ?DEBUG("CSR = ~p", [CSR]),
    {public_key:der_encode('CertificationRequest', CSR),
     State#state{cert_type = cert_type(CertKey), cert_key = CertKey}}.

-spec cert_type(priv_key()) -> cert_type().
cert_type(#'RSAPrivateKey'{}) -> rsa;
cert_type(#'ECPrivateKey'{}) -> ec.

signature_algorithm(#'ECPrivateKey'{}) ->
    ?'ecdsa-with-SHA256';
signature_algorithm(#'RSAPrivateKey'{}) ->
    ?'sha256WithRSAEncryption'.

algorithm(#'ECPrivateKey'{}) ->
    ?'id-ecPublicKey';
algorithm(#'RSAPrivateKey'{}) ->
    ?'rsaEncryption'.

-spec pubkey_from_privkey(priv_key()) -> pub_key().
pubkey_from_privkey(#'RSAPrivateKey'{modulus = Modulus,
				     publicExponent = Exp}) ->
    #'RSAPublicKey'{modulus = Modulus,
		    publicExponent = Exp};
pubkey_from_privkey(#'ECPrivateKey'{publicKey = Key}) ->
    #'ECPoint'{point = Key}.

-spec subject_pubkey(pub_key()) -> binary().
subject_pubkey(#'ECPoint'{point = Point}) ->
    Point;
subject_pubkey(#'RSAPublicKey'{} = Key) ->
    public_key:der_encode('RSAPublicKey', Key).

-spec der_params(priv_key()) -> binary().
der_params(#'ECPrivateKey'{parameters = Params}) ->
    public_key:der_encode('EcpkParameters', Params);
der_params(_) ->
    ?DER_NULL.

-spec pubkey_from_cert(cert()) -> pub_key().
pubkey_from_cert(Cert) ->
    TBSCert = Cert#'OTPCertificate'.tbsCertificate,
    PubKeyInfo = TBSCert#'OTPTBSCertificate'.subjectPublicKeyInfo,
    SubjPubKey = PubKeyInfo#'OTPSubjectPublicKeyInfo'.subjectPublicKey,
    case PubKeyInfo#'OTPSubjectPublicKeyInfo'.algorithm of
        #'PublicKeyAlgorithm'{
           algorithm = ?'rsaEncryption'} ->
            SubjPubKey;
        #'PublicKeyAlgorithm'{
           algorithm = ?'id-ecPublicKey'} ->
            SubjPubKey
    end.

-spec validate_cert_chain([cert(), ...], [binary(), ...], priv_key(), [cert()]) ->
				 valid | {bad_cert, bad_cert_reason()}.
validate_cert_chain([Cert|_] = Certs, DerCerts, PrivKey, CaCerts) ->
    case pubkey_from_privkey(PrivKey) == pubkey_from_cert(Cert) of
	false -> {bad_cert, key_mismatch};
	true ->
	    Last = lists:last(Certs),
	    case find_issuer_cert(Last, CaCerts) of
		{ok, CaCert} ->
		    case public_key:pkix_path_validation(
			   CaCert, lists:reverse(DerCerts), []) of
			{ok, _} -> valid;
			{error, {bad_cert, _} = Reason} -> Reason
		    end;
		error ->
		    case public_key:pkix_is_self_signed(Last) of
			true ->
			    {bad_cert, selfsigned_peer};
			false ->
			    {bad_cert, unknown_ca}
		    end
	    end
    end.

-spec find_issuer_cert(cert(), [cert()]) -> {ok, cert()} | error.
find_issuer_cert(Cert, [IssuerCert|IssuerCerts]) ->
    case public_key:pkix_is_issuer(Cert, IssuerCert) of
        true -> {ok, IssuerCert};
        false -> find_issuer_cert(Cert, IssuerCerts)
    end;
find_issuer_cert(_Cert, []) ->
    error.

%%%===================================================================
%%% JOSE idiotism
%%%===================================================================
-spec jose_json(state(), binary() | map(), binary() | string()) -> binary().
jose_json(State, JSON, URL) when is_map(JSON) ->
    jose_json(State, encode_json(JSON), URL);
jose_json(#state{account = {Key, AccURL}, nonce = Nonce} = State, Data, URL) ->
    PrivKey = jose_jwk:from_key(Key),
    PubKey = jose_jwk:to_public(PrivKey),
    AlgMap = case jose_jwk:signer(PrivKey) of
		 M when is_record(Key, 'RSAPrivateKey') ->
		     M#{<<"alg">> => <<"RS256">>};
		 M ->
		     M
	     end,
    JwsMap0 = #{<<"nonce">> => Nonce,
		<<"url">> => iolist_to_binary(URL)},
    JwsMap = case AccURL of
		 undefined ->
		     {_, BinaryPubKey} = jose_jwk:to_binary(PubKey),
		     PubKeyJson = jiffy:decode(BinaryPubKey),
		     JwsMap0#{<<"jwk">> => PubKeyJson};
		 _ ->
		     JwsMap0#{<<"kid">> => iolist_to_binary(AccURL)}
	     end,
    JwsObj = jose_jws:from(maps:merge(JwsMap, AlgMap)),
    ?DEBUG("JOSE payload: ~s~nJOSE protected: ~p", [Data, JwsObj]),
    {_, JoseJSON} = jose_jws:sign(PrivKey, Data, JwsObj),
    encode_json(JoseJSON).

-spec auth_key(state(), binary()) -> binary().
auth_key(#state{account = {PrivKey, _}}, Token) ->
    Thumbprint = jose_jwk:thumbprint(jose_jwk:from_key(PrivKey)),
    <<Token/binary, $., Thumbprint/binary>>.

-spec encode_json(map()) -> binary().
encode_json(JSON) ->
    iolist_to_binary(jiffy:encode(JSON)).

%%%===================================================================
%%% Misc
%%%===================================================================
-spec mk_http_error(term()) -> error_return().
mk_http_error(Reason) ->
    mk_error({http_error, Reason}).

-spec mk_codec_error(yconf:error_return()) -> error_return().
mk_codec_error({error, Reason, Ctx}) ->
    mk_error({codec_error, Reason, Ctx}).

-spec mk_error(error_reason()) -> error_return().
mk_error(Reason) ->
    {error, Reason}.

-spec current_time() -> integer().
current_time() ->
    erlang:monotonic_time(millisecond).

-spec get_timeout(state()) -> non_neg_integer().
get_timeout(#state{end_time = EndTime}) ->
    max(0, EndTime - current_time()).

-spec check_url(binary() | string()) -> string().
check_url(S) ->
    case yconf:validate(yconf:url(), iolist_to_binary(S)) of
	{ok, URL} -> binary_to_list(URL);
	_ -> erlang:error(badarg, [S])
    end.

-spec init_state(issue, binary() | string(), [binary() | string()], priv_key(),
		 [issue_option()]) -> state();
		(revoke, binary() | string(), cert(), priv_key(),
		 [revoke_option()]) -> state().
init_state(issue, DirURL, Domains, AccKey, Opts) ->
    State = #state{command = issue,
		   dir_url = check_url(DirURL),
		   domains = lists:map(fun iolist_to_binary/1, Domains),
		   account = {AccKey, undefined},
		   contact = [],
		   cert_type = ec,
		   ca_certs = [],
		   challenge_type = <<"http-01">>,
		   end_time = current_time() + ?DEFAULT_TIMEOUT},
    lists:foldl(
      fun({timeout, Timeout}, S) when is_integer(Timeout), Timeout > 0 ->
	      EndTime = current_time() + Timeout,
	      S#state{end_time = EndTime};
	 ({contact, Cs}, S) when is_list(Cs) ->
	      S#state{contact = lists:map(fun iolist_to_binary/1, Cs)};
	 ({cert_type, T}, S) when T == ec; T == rsa ->
	      S#state{cert_type = T};
	 ({cert_key, K}, S) ->
	      S#state{cert_key = K};
	 ({ca_certs, L}, S) when is_list(L) ->
	      S#state{ca_certs = L};
	 ({challenge_type, 'http-01'}, S) ->
	      S#state{challenge_type = <<"http-01">>};
	 ({challenge_fun, Fun}, S) when is_function(Fun, 1) ->
	      S#state{challenge_fun = Fun};
	 ({debug_fun, Fun}, S) when is_function(Fun, 2) ->
	      S#state{debug_fun = Fun};
	 (Opt, _) ->
	      erlang:error({bad_option, Opt})
      end, State, Opts);
init_state(revoke, DirURL, Cert, CertKey, Opts) ->
    State = #state{command = revoke,
		   dir_url = check_url(DirURL),
		   domains = [],
		   contact = [],
		   cert = Cert,
		   cert_key = CertKey,
		   ca_certs = [],
		   end_time = current_time() + ?DEFAULT_TIMEOUT},
    lists:foldl(
      fun({timeout, Timeout}, S) when is_integer(Timeout), Timeout > 0 ->
	      EndTime = current_time() + Timeout,
	      S#state{end_time = EndTime};
	 ({debug_fun, Fun}, S) when is_function(Fun, 2) ->
	      S#state{debug_fun = Fun};
	 (Opt, _) ->
	      erlang:error({bad_option, Opt})
      end, State, Opts).

-spec find_location([{string(), string()}]) -> string() | undefined.
find_location(Hdrs) ->
    find_location(Hdrs, undefined).

-spec find_location([{string(), string()}], T) -> string() | T.
find_location(Hdrs, Default) ->
    proplists:get_value("location", Hdrs, Default).

-spec split_challenges([{binary(), acme_codec:challenge_obj()}, ...]) ->
			      {Pending :: [{binary(), acme_codec:challenge_obj()}],
			       InProgress :: [{binary(), acme_codec:challenge_obj()}],
			       Valid :: [{binary(), acme_codec:challenge_obj()}],
			       InValid ::[{binary(), acme_codec:challenge_obj()}]}.
split_challenges(Challenges) ->
    split_challenges(Challenges, [], [], [], []).

split_challenges([{_, Challenge} = C|Cs], Pending, InProgress, Valid, Invalid) ->
    case maps:get(status, Challenge) of
	pending -> split_challenges(Cs, [C|Pending], InProgress, Valid, Invalid);
	processing -> split_challenges(Cs, Pending, [C|InProgress], Valid, Invalid);
	valid -> split_challenges(Cs, Pending, InProgress, [C|Valid], Invalid);
	invalid -> split_challenges(Cs, Pending, InProgress, Valid, [C|Invalid])
    end;
split_challenges([], Pending, InProgress, Valid, Invalid) ->
    {Pending, InProgress, Valid, Invalid}.
