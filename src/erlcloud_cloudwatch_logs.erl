-module(erlcloud_cloudwatch_logs).


-include("erlcloud_aws.hrl").


-define(API_VERSION, "2014-03-28").
-define(API_PREFIX, "Logs_20140328").
-define(SERVICE_NAME, "logs").
-define(DEFAULT_LIMIT, 50).
-define(DEFAULT_HEADERS, [
    {"content-type", "application/x-amz-json-1.1"},
    {"accept", "application/json"}
]).


-type access_key_id() :: string().
-type secret_access_key() :: string().
-type cw_host() :: string().


-type paging_token() :: string() | binary() | undefined.
-type log_group_name_prefix() :: string() | binary() | undefined.
-type limit() :: pos_integer() | undefined.


-type success_result_paged(ObjectType) :: {ok, [ObjectType], paging_token()}.
-type error_result() :: {error, Reason :: term()}.
-type result_paged(ObjectType) :: success_result_paged(ObjectType) | error_result().


-type log_group() :: jsx:json_term().

-type log_group_name() :: string() | binary() | undefined.
-type log_stream_name() :: string() | binary() | undefined.
-type success_create_log_stream() :: ok.
-type result_create_log_stream() :: success_create_log_stream() | error_result().

-type sequence_token() :: string() | binary() | undefined.
-type log_event_message() :: string() | binary().
-type log_event_timestamp() :: pos_integer().
-type log_event() :: {log_event_message(), log_event_timestamp()}.
-type log_events() :: [log_event()].
-type rejected_log_events_info() :: jsx:json_term() | undefined.
-type success_put_events() :: {ok, sequence_token()} | {ok, sequence_token(), rejected_log_events_info()}.
-type result_put_events() :: success_put_events() | error_result().

-type log_stream_name_prefix() :: string() | binary() | undefined.
-type descending() :: boolean().
-type log_stream_order() :: log_stream_name | last_event_time.
-type log_stream() :: jsx:json_term().

%% Library initialization
-export([
    configure/2,
    configure/3,
    new/2,
    new/3
]).


%% CloudWatch API
-export([
    describe_log_groups/0,
    describe_log_groups/1,
    describe_log_groups/2,
    describe_log_groups/3,
    describe_log_groups/4,

    create_log_stream/2,
    create_log_stream/3,

    put_log_events/3,
    put_log_events/4,
    put_log_events/5,

    describe_log_streams/1,
    describe_log_streams/2,
    describe_log_streams/3,
    describe_log_streams/4,
    describe_log_streams/5,
    describe_log_streams/7
]).


%%==============================================================================
%% Library initialization
%%==============================================================================


-spec configure(access_key_id(), secret_access_key()) -> ok.
configure(AccessKeyID, SecretAccessKey) ->
    put(aws_config, new(AccessKeyID, SecretAccessKey)),
    ok.


-spec configure(access_key_id(), secret_access_key(), cw_host()) -> ok.
configure(AccessKeyID, SecretAccessKey, Host) ->
    put(aws_config, new(AccessKeyID, SecretAccessKey, Host)),
    ok.


-spec new(access_key_id(), secret_access_key()) -> aws_config().
new(AccessKeyID, SecretAccessKey) ->
    #aws_config{
        access_key_id = AccessKeyID,
        secret_access_key = SecretAccessKey
    }.


-spec new(access_key_id(), secret_access_key(), cw_host()) -> aws_config().
new(AccessKeyID, SecretAccessKey, Host) ->
    #aws_config{
        access_key_id = AccessKeyID,
        secret_access_key = SecretAccessKey,
        cloudwatch_logs_host = Host
    }.


%%==============================================================================
%% CloudWatch API
%%==============================================================================


%%------------------------------------------------------------------------------
%% @doc
%%
%% DescribeLogGroups action
%% http://docs.aws.amazon.com/AmazonCloudWatchLogs/latest/APIReference/API_DescribeLogGroups.html
%%
%% @end
%%------------------------------------------------------------------------------
-spec describe_log_groups() -> result_paged(log_group()).
describe_log_groups() ->
    describe_log_groups(default_config()).


-spec describe_log_groups(
    aws_config() | log_group_name_prefix()
) -> result_paged(log_group()).
describe_log_groups(#aws_config{} = Config) ->
    describe_log_groups(undefined, Config);
describe_log_groups(LogGroupNamePrefix) ->
    describe_log_groups(LogGroupNamePrefix, default_config()).


-spec describe_log_groups(
    log_group_name_prefix(),
    aws_config()
) -> result_paged(log_group()).
describe_log_groups(LogGroupNamePrefix, Config) ->
    describe_log_groups(LogGroupNamePrefix, ?DEFAULT_LIMIT, Config).


-spec describe_log_groups(
    log_group_name_prefix(),
    limit(),
    aws_config()
) -> result_paged(log_group()).
describe_log_groups(LogGroupNamePrefix, Limit, Config) ->
    describe_log_groups(LogGroupNamePrefix, Limit, undefined, Config).


-spec describe_log_groups(
    log_group_name_prefix(),
    limit(),
    paging_token(),
    aws_config()
) -> result_paged(log_group()).
describe_log_groups(LogGroupNamePrefix, Limit, PrevToken, Config) when is_list(LogGroupNamePrefix) ->
    describe_log_groups(list_to_binary(LogGroupNamePrefix), Limit, PrevToken, Config);
describe_log_groups(LogGroupNamePrefix, Limit, PrevToken, Config) when is_list(PrevToken) ->
    describe_log_groups(LogGroupNamePrefix, Limit, list_to_binary(PrevToken), Config);
describe_log_groups(LogGroupNamePrefix, Limit, PrevToken, Config) ->
    case cw_request(Config, "DescribeLogGroups", [
        {<<"limit">>, Limit},
        {<<"logGroupNamePrefix">>, LogGroupNamePrefix},
        {<<"nextToken">>, PrevToken}
    ]) of
        {ok, Data} ->
            LogGroups = proplists:get_value(<<"logGroups">>, Data, []),
            NextToken = proplists:get_value(<<"nextToken">>, Data, undefined),
            {ok, LogGroups, NextToken};
        {error, Reason} ->
            {error, Reason}
    end.

-spec create_log_stream(
    log_group_name(),
    log_stream_name()
) -> result_create_log_stream().
create_log_stream(LogGroupName, LogStreamName) ->
    create_log_stream(LogGroupName, LogStreamName, default_config()).

-spec create_log_stream(
    log_group_name(),
    log_stream_name(),
    aws_config()
) -> result_create_log_stream().
create_log_stream(LogGroupName, LogStreamName, Config) when is_list(LogGroupName)->
    create_log_stream(list_to_binary(LogGroupName), LogStreamName, Config);
create_log_stream(LogGroupName, LogStreamName, Config) when is_list(LogStreamName)->
    create_log_stream(LogGroupName, list_to_binary(LogStreamName), Config);
create_log_stream(LogGroupName, LogStreamName, Config) ->
    case cw_request(Config, "CreateLogStream", [
        {<<"logGroupName">>, LogGroupName},
        {<<"logStreamName">>, LogStreamName}
    ]) of
        {ok, _} -> ok;
        {error, Reason} -> {error, Reason}
    end.

-spec put_log_events(
    log_events(),
    log_group_name(),
    log_stream_name()
) -> result_put_events().
put_log_events(LogEvents, LogGroupName, LogStreamName) ->
    put_log_events(LogEvents, LogGroupName, LogStreamName, undefined).

-spec put_log_events(
    log_events(),
    log_group_name(),
    log_stream_name(),
    sequence_token()
) -> result_put_events().
put_log_events(LogEvents, LogGroupName, LogStreamName, SequenceToken) ->
    put_log_events(LogEvents, LogGroupName, LogStreamName, SequenceToken, default_config()).

-spec put_log_events(
    log_events(),
    log_group_name(),
    log_stream_name(),
    sequence_token(),
    aws_config()
) -> result_put_events().
put_log_events(LogEvents, LogGroupName, LogStreamName, SequenceToken, Config) ->
    case cw_request(Config, "PutLogEvents",make_put_log_events_params(
        LogEvents,
        LogGroupName,
        LogStreamName,
        SequenceToken))
    of
        {ok, Data} ->
            NextSequenceToken = proplists:get_value(<<"nextSequenceToken">>, Data, undefined),
            RejectedLogEventsInfo = proplists:get_value(<<"rejectedLogEventsInfo">>, Data, undefined),
            {ok, NextSequenceToken, RejectedLogEventsInfo};
        {error, Reason} ->
            {error, Reason}
    end.

-spec describe_log_streams(
    log_group_name()
) -> result_paged(log_stream()).
describe_log_streams(LogGroupName) ->
    describe_log_streams(undefined, undefined, LogGroupName, undefined, undefined, undefined, default_config()).

-spec describe_log_streams(
    log_group_name(),
    aws_config() | log_stream_name_prefix()
) -> result_paged(log_stream()).
describe_log_streams(LogGroupName, #aws_config{} = Config) ->
    describe_log_streams(undefined, undefined, LogGroupName, undefined, undefined, undefined, Config);

describe_log_streams(LogGroupName, LogStreamPrefix) ->
    describe_log_streams(undefined, undefined, LogGroupName, LogStreamPrefix, undefined, undefined, default_config()).

-spec describe_log_streams(
    log_group_name(),
    log_stream_name_prefix(),
    aws_config()
) -> result_paged(log_stream()).
describe_log_streams(LogGroupName, LogStreamPrefix, #aws_config{} = Config) ->
    describe_log_streams(undefined, undefined, LogGroupName, LogStreamPrefix, undefined, undefined, Config).


-spec describe_log_streams(
    limit(),
    log_group_name(),
    log_stream_name_prefix(),
    aws_config()
) -> result_paged(log_stream()).
describe_log_streams(Limit, LogGroupName, LogStreamPrefix, #aws_config{} = Config) ->
    describe_log_streams(undefined, Limit, LogGroupName, LogStreamPrefix, undefined, undefined, Config).

-spec describe_log_streams(
    limit(),
    log_group_name(),
    log_stream_name_prefix(),
    paging_token(),
    aws_config()
) -> result_paged(log_stream()).
describe_log_streams(Limit, LogGroupName, LogStreamPrefix, PrevToken, #aws_config{} = Config) ->
    describe_log_streams(undefined, Limit, LogGroupName, LogStreamPrefix, PrevToken, undefined, Config).

-spec describe_log_streams(
    descending(),
    limit(),
    log_group_name(),
    log_stream_name_prefix(),
    paging_token(),
    log_stream_order(),
    aws_config()
) -> result_paged(log_stream()).
describe_log_streams(Descending, Limit, LogGroupName, LogStreamPrefix, PrevToken, Order, Config) when is_list(LogGroupName) ->
    describe_log_streams(Descending, Limit, list_to_binary(LogGroupName), LogStreamPrefix, PrevToken, Order, Config);
describe_log_streams(Descending, Limit, LogGroupName, LogStreamPrefix, PrevToken, Order, Config) when is_list(LogStreamPrefix) ->
    describe_log_streams(Descending, Limit, LogGroupName, list_to_binary(LogStreamPrefix), PrevToken, Order, Config);
describe_log_streams(Descending, Limit, LogGroupName, LogStreamPrefix, PrevToken, Order, Config) when is_list(PrevToken) ->
    describe_log_streams(Descending, Limit, LogGroupName, LogStreamPrefix, list_to_binary(PrevToken), Order, Config);
describe_log_streams(Descending, Limit, LogGroupName, LogStreamPrefix, PrevToken, Order, Config) ->
    OrderBin = log_stream_order_to_binary(Order),
    case cw_request(Config, "DescribeLogStreams", [
        {<<"descending">>, Descending},
        {<<"limit">>, Limit},
        {<<"logGroupName">>, LogGroupName},
        {<<"logStreamNamePrefix">>, LogStreamPrefix},
        {<<"nextToken">>, PrevToken},
        {<<"orderBy">>, OrderBin}
    ]) of
        {ok, Data} ->
            LogStreams = proplists:get_value(<<"logStreams">>, Data, []),
            NextToken = proplists:get_value(<<"nextToken">>, Data, undefined),
            {ok, LogStreams, NextToken};
        {error, Reason} ->
            {error, Reason}
    end.

%%==============================================================================
%% Internal functions
%%==============================================================================


default_config() ->
    erlcloud_aws:default_config().


cw_request(Config, Action, Params) ->
    case erlcloud_aws:update_config(Config) of
        {ok, NewConfig} ->
            RequestBody = make_request_body(
                Action, Params
            ),
            RequestHeaders = make_request_headers(
                NewConfig, Action, RequestBody
            ),
            case erlcloud_aws:aws_request_form_raw(
                post,
                NewConfig#aws_config.cloudwatch_logs_scheme,
                NewConfig#aws_config.cloudwatch_logs_host,
                NewConfig#aws_config.cloudwatch_logs_port,
                "/",
                RequestBody,
                RequestHeaders,
                NewConfig
            ) of
                {ok, ResponseBody} ->
                    Resp = try jsx:decode(ResponseBody)
                           catch
                               _:_ -> {}
                           end,
                    {ok, Resp};
                {error, Reason} ->
                    {error, Reason}
            end;
        {error, Reason} ->
            {error, Reason}
    end.


make_request_headers(Config, Action, Body) ->
    lists:append(make_signed_headers(Config, Action, Body), ?DEFAULT_HEADERS).


make_signed_headers(Config, Action, Body) ->
    #aws_config{cloudwatch_logs_host = Host} = Config,
    Target = lists:append([?API_PREFIX, ".", Action]),
    Headers = [{"host", Host}, {"x-amz-target", Target}],
    Region = erlcloud_aws:aws_region_from_host(Host),
    erlcloud_aws:sign_v4_headers(Config, Headers, Body, Region, ?SERVICE_NAME).


make_request_body(Action, RequestParams) ->
    DefaultParams = [{<<"Action">>, Action}, {<<"Version">>, ?API_VERSION}],
    Params = lists:append(DefaultParams, RequestParams),
    jsx:encode(prepare_request_params(Params)).


prepare_request_params(Params) ->
    lists:filtermap(fun prepare_request_param/1, Params).


prepare_request_param({_Key, undefined}) ->
    false;

prepare_request_param({Key, Value}) ->
    {true, {Key, Value}}.

make_put_log_events_params(LogEvents, LogGroupName, LogStreamName, SequenceToken) when is_list(LogGroupName) ->
    make_put_log_events_params(LogEvents, list_to_binary(LogGroupName), LogStreamName, SequenceToken);
make_put_log_events_params(LogEvents, LogGroupName, LogStreamName, SequenceToken) when is_list(LogStreamName) ->
    make_put_log_events_params(LogEvents, LogGroupName, list_to_binary(LogStreamName), SequenceToken);
make_put_log_events_params(LogEvents, LogGroupName, LogStreamName, SequenceToken) when is_list(SequenceToken) ->
    make_put_log_events_params(LogEvents, LogGroupName, LogStreamName, list_to_binary(SequenceToken));
make_put_log_events_params(LogEvents, LogGroupName, LogStreamName, undefined) ->
    [
        {<<"logEvents">>, LogEvents},
        {<<"logGroupName">>, LogGroupName},
        {<<"logStreamName">>, LogStreamName}
    ];

make_put_log_events_params(LogEvents, LogGroupName, LogStreamName, SequenceToken) ->
    [
        {<<"logEvents">>, LogEvents},
        {<<"logGroupName">>, LogGroupName},
        {<<"logStreamName">>, LogStreamName},
        {<<"sequenceToken">>, SequenceToken}
    ].

log_stream_order_to_binary(log_stream_name) -> <<"LogStreamName">>;
log_stream_order_to_binary(log_event_time) -> <<"LogEventTime">>;
log_stream_order_to_binary(_) -> undefined.