%%%-------------------------------------------------------------------
%%% @author Evgeny Khramtsov <ekhramtsov@process-one.net>
%%% @copyright (C) 2002-2024 ProcessOne, SARL. All Rights Reserved.
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
-module(p1_acme_codec).

%% API
-export([decode_dir_obj/1]).
-export([decode_acc_obj/1]).
-export([decode_order_obj/1]).
-export([decode_auth_obj/1]).
-export([decode_err_obj/1]).

-type acme_error() :: accountDoesNotExist |
		      alreadyRevoked |
		      badCSR |
		      badNonce |
		      badPublicKey |
		      badRevocationReason |
		      badSignatureAlgorithm |
		      caa |
		      compound |
		      connection |
		      dns |
		      externalAccountRequired |
		      incorrectResponse |
		      invalidContact |
		      malformed |
		      orderNotReady |
		      rateLimited |
		      rejectedIdentifier |
		      serverInternal |
		      tls |
		      unauthorized |
		      unsupportedContact |
		      unsupportedIdentifier |
		      userActionRequired |
		      binary().

-type dir_obj() :: #{newNonce := binary(),
		     newAccount := binary(),
		     newOrder := binary(),
		     revokeCert := binary(),
		     keyChange := binary(),
		     newAuthz => binary(),
		     meta =>
			 #{caaIdentities => [binary()],
			   termsOfService => binary(),
			   website => binary(),
			   externalAccountRequired => boolean()}}.

-type acc_obj() :: #{status := valid | deactivated | revoked,
		     contact => [binary()],
		     termsOfServiceAgreed => boolean(),
		     externalAccountBinding => _,
		     orders => binary()}.

-type order_obj() :: #{status := pending | ready | processing | valid | invalid,
		       identifiers := [identifier_obj(), ...],
		       authorizations := [binary()],
		       finalize := binary(),
		       expires => erlang:timestamp(),
		       notBefore => erlang:timestamp(),
		       notAfter => erlang:timestamp(),
		       error => err_obj(),
		       certificate => binary()}.

-type auth_obj() :: #{identifier := identifier_obj(),
		      status := pending | valid | invalid |
		                deactivated | expired | revoked,
		      expires => erlang:timestamp(),
		      challenges => [challenge_obj(), ...],
		      wildcard => boolean()}.

-type err_obj() :: #{type := acme_error(),
		     detail => binary(),
		     status => pos_integer()}.

-type identifier_obj() :: #{type := dns, value := binary()}.

-type challenge_obj() :: #{type := binary(),
			   url := binary(),
			   status := pending | processing | valid | invalid,
			   validated => erlang:timestamp(),
			   token => binary(),
			   error => err_obj()}.

-export_type([acme_error/0, dir_obj/0, acc_obj/0, order_obj/0, auth_obj/0,
	      err_obj/0, identifier_obj/0, challenge_obj/0]).

%%%===================================================================
%%% API
%%%===================================================================
-spec decode_dir_obj(map()) -> {ok, dir_obj()} | yconf:error_return().
decode_dir_obj(JSON) ->
    Validator = yconf:options(
		  #{newNonce => yconf:url(),
		    newAccount => yconf:url(),
		    newOrder => yconf:url(),
		    newAuthz => yconf:url(),
		    revokeCert => yconf:url(),
		    keyChange => yconf:url(),
		    meta => yconf:options(
			      #{caaIdentities => yconf:list(yconf:binary()),
				termsOfService => yconf:url(),
				website => yconf:url(),
				externalAccountRequired => yconf:bool(),
				'_' => yconf:any()},
			      [unique, {return, map}]),
		    '_' => yconf:any()},
		  [unique, {return, map},
		   {required, [newNonce, newAccount, newOrder,
			       revokeCert, keyChange]}]),
    decode(Validator, JSON).

-spec decode_acc_obj(map()) -> {ok, acc_obj()} | yconf:error_return().
decode_acc_obj(JSON) ->
    Validator = yconf:options(
		  #{status => yconf:enum([valid, deactivated, revoked]),
		    contact => yconf:list(yconf:binary()),
		    termsOfServiceAgreed => yconf:bool(),
		    externalAccountBinding => yconf:any(),
		    orders => yconf:url(),
		    '_' => yconf:any()},
		  [unique, {return, map}, {required, [status]}]),
    decode(Validator, JSON).

-spec decode_order_obj(map()) -> {ok, order_obj()} | yconf:error_return().
decode_order_obj(JSON) ->
    Validator = yconf:options(
		  #{status => yconf:enum([pending, ready, processing, valid, invalid]),
		    expires => timestamp_validator(),
		    identifiers => yconf:non_empty(yconf:list(identifier_validator())),
		    notBefore => timestamp_validator(),
		    notAfter => timestamp_validator(),
		    error => err_obj_validator(),
		    authorizations => yconf:non_empty(yconf:list(yconf:url())),
		    finalize => yconf:url(),
		    certificate => yconf:url(),
		    '_' => yconf:any()},
		  [unique, {return, map},
		   {required, [status, identifiers, authorizations, finalize]}]),
    decode(Validator, JSON).

-spec decode_auth_obj(map()) -> {ok, auth_obj()} | yconf:error_return().
decode_auth_obj(JSON) ->
    Validator = yconf:options(
		  #{identifier => identifier_validator(),
		    status => yconf:enum([pending, valid, invalid,
					  deactivated, expired, revoked]),
		    expires => timestamp_validator(),
		    challenges => yconf:non_empty(yconf:list(challenge_validator())),
		    wildcard => yconf:bool(),
		    '_' => yconf:any()},
		  [unique, {return, map},
		   {required, [identifier, status]}]),
    decode(Validator, JSON).

-spec decode_err_obj(map()) -> {ok, err_obj()} | yconf:error_return().
decode_err_obj(JSON) ->
    decode(err_obj_validator(), JSON).

%%%===================================================================
%%% Internal functions
%%%===================================================================
decode(Validator, JSON) ->
    yconf:validate(Validator, json_to_yaml(JSON)).

json_to_yaml(M) when is_map(M) ->
    lists:filtermap(
      fun({Key, Val}) ->
	      try binary_to_existing_atom(Key, latin1) of
		  Opt -> {true, {Opt, json_to_yaml(Val)}}
	      catch _:_ ->
		      false
	      end
      end, maps:to_list(M));
json_to_yaml(L) when is_list(L) ->
    lists:map(fun json_to_yaml/1, L);
json_to_yaml(Term) ->
    Term.

%%%===================================================================
%%% Validators
%%%===================================================================
identifier_validator() ->
    yconf:options(
      #{type => yconf:enum([dns]),
	value => yconf:binary(),
	'_' => yconf:any()},
      [unique, {return, map}, {required, [type, value]}]).

err_obj_validator() ->
    yconf:options(
      #{type => acme_error_validator(),
	detail => yconf:binary(),
	status => yconf:pos_int(),
	'_' => yconf:any()},
      [unique, {return, map}, {required, [type]}]).

challenge_validator() ->
    yconf:options(
      #{type => yconf:binary(),
	url => yconf:url(),
	status => yconf:enum([pending, processing, valid, invalid]),
	validated => timestamp_validator(),
	token => yconf:binary(),
	error => err_obj_validator(),
	'_' => yconf:any()},
      [unique, {return, map},
       {required, [type, url, status]}]).

timestamp_validator() ->
    fun(S) ->
	    B = (yconf:binary())(S),
	    try try_decode_timestamp(B)
	    catch _:_ -> yconf:fail(?MODULE, {bad_timestamp, B})
	    end
    end.

acme_error_validator() ->
    fun(S) ->
	    URL = (yconf:binary())(S),
	    case URL of
		<<"urn:ietf:params:acme:error:", Type/binary>> ->
		    (yconf:enum(acme_errors()))(Type);
		_ ->
		    URL
	    end
    end.

-spec acme_errors() -> [acme_error()].
acme_errors() ->
    [accountDoesNotExist,
     alreadyRevoked,
     badCSR,
     badNonce,
     badPublicKey,
     badRevocationReason,
     badSignatureAlgorithm,
     caa,
     compound,
     connection,
     dns,
     externalAccountRequired,
     incorrectResponse,
     invalidContact,
     malformed,
     orderNotReady,
     rateLimited,
     rejectedIdentifier,
     serverInternal,
     tls,
     unauthorized,
     unsupportedContact,
     unsupportedIdentifier,
     userActionRequired].

try_decode_timestamp(<<Y:4/binary, $-, Mo:2/binary, $-, D:2/binary, $T,
                       H:2/binary, $:, Mi:2/binary, $:, S:2/binary, T/binary>>) ->
    Date = {to_integer(Y, 1970, 9999), to_integer(Mo, 1, 12), to_integer(D, 1, 31)},
    Time = {to_integer(H, 0, 23), to_integer(Mi, 0, 59), to_integer(S, 0, 59)},
    {MS, {TZH, TZM}} = try_decode_fraction(T),
    Seconds = calendar:datetime_to_gregorian_seconds({Date, Time}) -
        calendar:datetime_to_gregorian_seconds({{1970,1,1}, {0,0,0}}) -
        TZH * 60 * 60 - TZM * 60,
    {Seconds div 1000000, Seconds rem 1000000, MS}.

try_decode_fraction(<<$., T/binary>>) ->
    {match, [V]} = re:run(T, <<"^[0-9]+">>, [{capture, [0], list}]),
    Size = length(V),
    <<_:Size/binary, TZD/binary>> = T,
    {list_to_integer(string:left(V, 6, $0)),
     try_decode_tzd(TZD)};
try_decode_fraction(TZD) ->
    {0, try_decode_tzd(TZD)}.

try_decode_tzd(<<$Z>>) ->
    {0, 0};
try_decode_tzd(<<$-, H:2/binary, $:, M:2/binary>>) ->
    {-1 * to_integer(H, 0, 12), to_integer(M, 0, 59)};
try_decode_tzd(<<$+, H:2/binary, $:, M:2/binary>>) ->
    {to_integer(H, 0, 12), to_integer(M, 0, 59)}.

to_integer(S, Min, Max) ->
    case binary_to_integer(S) of
        I when I >= Min, I =< Max ->
            I
    end.
