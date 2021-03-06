-module(erlcloud_cloudwatch_logs_tests).


-include_lib("eunit/include/eunit.hrl").


%% Unit tests for cloudwatch.
%% These tests work by using meck to mock erlcloud_httpc. There are two classes
%% of test: input and output.
%%
%% Input tests verify that different function args produce the desired query
%% parameters.
%%
%% An input test list provides a list of funs and the parameters that are
%% expected to result.
%%
%% Output tests verify that the http response produces the correct return
%% from the fun.
%% An output test lists provides a list of response bodies and the
%% expected return.


%% The _cloudwatch_test macro provides line number annotation to a test,
%% similar to _test, but doesn't wrap in a fun
-define(_cloudwatch_test(T), {?LINE, T}).
%% The _f macro is a terse way to wrap code in a fun.
%% Similar to _test but doesn't annotate with a line number
-define(_f(F), fun() -> F end).


-define(ACCESS_KEY_ID, string:copies("A", 20)).
-define(SECRET_ACCESS_KEY, string:copies("a", 40)).


-define(API_VERSION, <<"2014-03-28">>).
-define(DEFAULT_LIMIT, 50).
-define(NON_DEFAULT_LIMIT, 100).
-define(LOG_GROUP_NAME_PREFIX, <<"/aws/apigateway/welcome">>).
-define(PAGING_TOKEN, <<"arn:aws:logs:us-east-1:352773894028:log-group:/aws/apigateway/welcome:*">>).


-define(LOG_GROUP, [
    {<<"arn">>, <<"arn:aws:logs:us-east-1:352773894028:log-group:/aws/apigateway/welcome:*">>},
    {<<"creationTime">>, 1476283527335},
    {<<"logGroupName">>, <<"/aws/apigateway/welcome">>},
    {<<"metricFilterCount">>, 0},
    {<<"retentionInDays">>, 10},
    {<<"storedBytes">>, 85}
]).

-define(LOG_STREAM_NAME_PREFIX, <<"my-log-stream-1">>).
-define(DESCEDING_ORDER, true).
-define(ORDER_BY_LOG_STREAM_NAME_ATOM, log_stream_name).
-define(ORDER_BY_LOG_STREAM_NAME_BIN, <<"LogStreamName">>).
-define(ORDER_BY_LOG_EVENT_TIME_ATOM, log_event_time).
-define(ORDER_BY_LOG_EVENT_TIME_BIN, <<"LogEventTime">>).

-define(LOG_STREAMS, [
    {<<"arn">>, <<"arn:aws:logs:us-east-1:123456789012:log-group:my-log-group-1:log-stream:my-log-stream-1">>},
    {<<"creationTime">>, 1393545600000},
    {<<"firstEventTimestamp">>, 1393545600000},
    {<<"lastEventTimestamp">>, 1393567800000},
    {<<"lastIngestionTime">>, 1393589200000},
    {<<"logStreamName">>, <<"my-log-stream-1">>},
    {<<"storedBytes">>, 5242880},
    {<<"uploadSequenceToken">>, <<"07622379445839968487886029673945314100949536701251562127">>}
  ]).


%%==============================================================================
%% Test generator functions
%%==============================================================================


erlcloud_cloudwatch_test_() ->
    {foreach, fun start/0, fun stop/1, [
        fun describe_log_groups_input_tests/1,
        fun describe_log_groups_output_tests/1,
        fun describe_log_streams_input_tests/1,
        fun describe_log_streams_output_tests/1
    ]}.


%%==============================================================================
%% Setup functions
%%==============================================================================


start() ->
    meck:new(erlcloud_httpc).


stop(_) ->
    meck:unload(erlcloud_httpc).


%%==============================================================================
%% Test functions
%%==============================================================================


describe_log_groups_input_tests(_) ->
    input_tests(jsx:encode([{<<"logGroups">>, []}]), [
        ?_cloudwatch_test(
            {"Tests describing log groups with no parameters",
             ?_f(erlcloud_cloudwatch_logs:describe_log_groups()),
             [{<<"Action">>, <<"DescribeLogGroups">>},
              {<<"Version">>, ?API_VERSION},
              {<<"limit">>, ?DEFAULT_LIMIT}]}
        ),
        ?_cloudwatch_test(
            {"Tests describing log groups with custom AWS config provided",
             ?_f(erlcloud_cloudwatch_logs:describe_log_groups(
                 erlcloud_aws:default_config()
             )),
             [{<<"Action">>, <<"DescribeLogGroups">>},
              {<<"Version">>, ?API_VERSION},
              {<<"limit">>, ?DEFAULT_LIMIT}]}
        ),
        ?_cloudwatch_test(
            {"Tests describing log groups with log group name prefix provided",
             ?_f(erlcloud_cloudwatch_logs:describe_log_groups(
                 ?LOG_GROUP_NAME_PREFIX
             )),
             [{<<"Action">>, <<"DescribeLogGroups">>},
              {<<"Version">>, ?API_VERSION},
              {<<"limit">>, ?DEFAULT_LIMIT},
              {<<"logGroupNamePrefix">>, ?LOG_GROUP_NAME_PREFIX}]}
        ),
        ?_cloudwatch_test(
            {"Tests describing log groups with custom AWS config and "
             "log group name prefix provided",
             ?_f(erlcloud_cloudwatch_logs:describe_log_groups(
                 ?LOG_GROUP_NAME_PREFIX,
                 erlcloud_aws:default_config()
             )),
             [{<<"Action">>, <<"DescribeLogGroups">>},
              {<<"Version">>, ?API_VERSION},
              {<<"limit">>, ?DEFAULT_LIMIT},
              {<<"logGroupNamePrefix">>, ?LOG_GROUP_NAME_PREFIX}]}
        ),
        ?_cloudwatch_test(
            {"Tests describing log groups with custom AWS config, "
             "log group name prefix and limit provided",
             ?_f(erlcloud_cloudwatch_logs:describe_log_groups(
                 ?LOG_GROUP_NAME_PREFIX,
                 ?NON_DEFAULT_LIMIT,
                 erlcloud_aws:default_config()
             )),
             [{<<"Action">>, <<"DescribeLogGroups">>},
              {<<"Version">>, ?API_VERSION},
              {<<"limit">>, ?NON_DEFAULT_LIMIT},
              {<<"logGroupNamePrefix">>, ?LOG_GROUP_NAME_PREFIX}]}
        ),
        ?_cloudwatch_test(
            {"Tests describing log groups with custom AWS config, log group "
             "name prefix, limit and pagination token provided",
             ?_f(erlcloud_cloudwatch_logs:describe_log_groups(
                 ?LOG_GROUP_NAME_PREFIX,
                 ?NON_DEFAULT_LIMIT,
                 ?PAGING_TOKEN,
                 erlcloud_aws:default_config()
             )),
             [{<<"Action">>, <<"DescribeLogGroups">>},
              {<<"Version">>, ?API_VERSION},
              {<<"limit">>, ?NON_DEFAULT_LIMIT},
              {<<"nextToken">>, ?PAGING_TOKEN},
              {<<"logGroupNamePrefix">>, ?LOG_GROUP_NAME_PREFIX}]}
        )
    ]).


describe_log_groups_output_tests(_) ->
    output_tests(?_f(erlcloud_cloudwatch_logs:describe_log_groups()), [
        ?_cloudwatch_test(
            {"Tests describing all log groups",
             jsx:encode([{<<"logGroups">>, [?LOG_GROUP]}]),
             {ok, [?LOG_GROUP], undefined}}
        )
    ]).


describe_log_streams_input_tests(_) ->
  input_tests(jsx:encode([{<<"logStreams">>, []}]), [
    ?_cloudwatch_test(
      {"Tests describing log streams with log group name provided",
        ?_f(erlcloud_cloudwatch_logs:describe_log_streams(
          ?LOG_GROUP_NAME_PREFIX
        )),
        [{<<"Action">>, <<"DescribeLogStreams">>},
          {<<"Version">>, ?API_VERSION},
          {<<"limit">>, ?DEFAULT_LIMIT},
          {<<"logGroupName">>, ?LOG_GROUP_NAME_PREFIX}]}
    ),
    ?_cloudwatch_test(
      {"Tests describing log groups with custom AWS config and"
      "log group name provided",
        ?_f(erlcloud_cloudwatch_logs:describe_log_streams(
          ?LOG_GROUP_NAME_PREFIX,
          erlcloud_aws:default_config()
        )),
        [{<<"Action">>, <<"DescribeLogStreams">>},
          {<<"Version">>, ?API_VERSION},
          {<<"limit">>, ?DEFAULT_LIMIT},
          {<<"logGroupName">>, ?LOG_GROUP_NAME_PREFIX}]}
    ),
    ?_cloudwatch_test(
      {"Tests describing log groups with log group name and "
      "log stream name prefix provided",
        ?_f(erlcloud_cloudwatch_logs:describe_log_streams(
          ?LOG_GROUP_NAME_PREFIX,
          ?LOG_STREAM_NAME_PREFIX
        )),
        [{<<"Action">>, <<"DescribeLogStreams">>},
          {<<"Version">>, ?API_VERSION},
          {<<"limit">>, ?DEFAULT_LIMIT},
          {<<"logGroupName">>, ?LOG_GROUP_NAME_PREFIX},
          {<<"logStreamNamePrefix">>, ?LOG_STREAM_NAME_PREFIX}]}
    ),
    ?_cloudwatch_test(
      {"Tests describing log groups with custom AWS config, "
      "log group name and log stream name prefix provided",
        ?_f(erlcloud_cloudwatch_logs:describe_log_streams(
          ?LOG_GROUP_NAME_PREFIX,
          ?LOG_STREAM_NAME_PREFIX,
          erlcloud_aws:default_config()
        )),
        [{<<"Action">>, <<"DescribeLogStreams">>},
          {<<"Version">>, ?API_VERSION},
          {<<"limit">>, ?DEFAULT_LIMIT},
          {<<"logGroupName">>, ?LOG_GROUP_NAME_PREFIX},
          {<<"logStreamNamePrefix">>, ?LOG_STREAM_NAME_PREFIX}]}
    ),
    ?_cloudwatch_test(
      {"Tests describing log groups with custom AWS config, "
      "log group name and log stream name prefix and limit provided",
        ?_f(erlcloud_cloudwatch_logs:describe_log_streams(
          ?NON_DEFAULT_LIMIT,
          ?LOG_GROUP_NAME_PREFIX,
          ?LOG_STREAM_NAME_PREFIX,
          erlcloud_aws:default_config()
        )),
        [{<<"Action">>, <<"DescribeLogStreams">>},
          {<<"Version">>, ?API_VERSION},
          {<<"limit">>, ?NON_DEFAULT_LIMIT},
          {<<"logGroupName">>, ?LOG_GROUP_NAME_PREFIX},
          {<<"logStreamNamePrefix">>, ?LOG_STREAM_NAME_PREFIX}]}
    ),
    ?_cloudwatch_test(
      {"Tests describing log groups with custom AWS config, "
      "log group name, log stream name prefix, limit and pagination token provided",
        ?_f(erlcloud_cloudwatch_logs:describe_log_streams(
          ?NON_DEFAULT_LIMIT,
          ?LOG_GROUP_NAME_PREFIX,
          ?LOG_STREAM_NAME_PREFIX,
          ?PAGING_TOKEN,
          erlcloud_aws:default_config()
        )),
        [{<<"Action">>, <<"DescribeLogStreams">>},
          {<<"Version">>, ?API_VERSION},
          {<<"limit">>, ?NON_DEFAULT_LIMIT},
          {<<"nextToken">>, ?PAGING_TOKEN},
          {<<"logGroupName">>, ?LOG_GROUP_NAME_PREFIX},
          {<<"logStreamNamePrefix">>, ?LOG_STREAM_NAME_PREFIX}]}
    ),
    ?_cloudwatch_test(
      {"Tests describing log groups with custom AWS config, "
      "log group name, log stream name prefix, limit, pagination token, "
      "descending order by log stream name provided",
        ?_f(erlcloud_cloudwatch_logs:describe_log_streams(
          ?DESCEDING_ORDER,
          ?NON_DEFAULT_LIMIT,
          ?LOG_GROUP_NAME_PREFIX,
          ?LOG_STREAM_NAME_PREFIX,
          ?PAGING_TOKEN,
          ?ORDER_BY_LOG_STREAM_NAME_ATOM,
          erlcloud_aws:default_config()
        )),
        [{<<"Action">>, <<"DescribeLogStreams">>},
          {<<"Version">>, ?API_VERSION},
          {<<"descending">>, ?DESCEDING_ORDER},
          {<<"limit">>, ?NON_DEFAULT_LIMIT},
          {<<"nextToken">>, ?PAGING_TOKEN},
          {<<"logGroupName">>, ?LOG_GROUP_NAME_PREFIX},
          {<<"logStreamNamePrefix">>, ?LOG_STREAM_NAME_PREFIX},
          {<<"orderBy">>, ?ORDER_BY_LOG_STREAM_NAME_BIN}]}
    ),
    ?_cloudwatch_test(
      {"Tests describing log groups with custom AWS config, "
      "log group name, log stream name prefix, limit, pagination token, "
      "descending order by log event time provided",
        ?_f(erlcloud_cloudwatch_logs:describe_log_streams(
          ?DESCEDING_ORDER,
          ?NON_DEFAULT_LIMIT,
          ?LOG_GROUP_NAME_PREFIX,
          ?LOG_STREAM_NAME_PREFIX,
          ?PAGING_TOKEN,
          ?ORDER_BY_LOG_EVENT_TIME_ATOM,
          erlcloud_aws:default_config()
        )),
        [{<<"Action">>, <<"DescribeLogStreams">>},
          {<<"Version">>, ?API_VERSION},
          {<<"descending">>, ?DESCEDING_ORDER},
          {<<"limit">>, ?NON_DEFAULT_LIMIT},
          {<<"nextToken">>, ?PAGING_TOKEN},
          {<<"logGroupName">>, ?LOG_GROUP_NAME_PREFIX},
          {<<"logStreamNamePrefix">>, ?LOG_STREAM_NAME_PREFIX},
          {<<"orderBy">>, ?ORDER_BY_LOG_EVENT_TIME_BIN}]}
    )
  ]).


describe_log_streams_output_tests(_) ->
  output_tests(?_f(erlcloud_cloudwatch_logs:describe_log_streams(
    ?LOG_GROUP_NAME_PREFIX
  )), [
    ?_cloudwatch_test(
      {"Tests describing all log streams",
        jsx:encode([{<<"logStreams">>, [?LOG_STREAMS]}]),
        {ok, [?LOG_STREAMS], undefined}}
    )
  ]).

%%==============================================================================
%% Internal functions
%%==============================================================================


input_tests(ResponseBody, Tests) ->
    [input_test(ResponseBody, Test) || Test <- Tests].


input_test(ResponseBody, {Line, {Description, Fun, ExpectedParams}}) ->
    {Description, {Line,
        fun() ->
            meck:expect(
                erlcloud_httpc,
                request,
                fun(_Url, post, _Headers, RequestBody, _Timeout, _Config) ->
                    ActualParams = jsx:decode(RequestBody),
                    ?assertEqual(sort_json(ExpectedParams), sort_json(ActualParams)),
                    {ok, {{200, "OK"}, [], ResponseBody}}
                end
            ),
            erlcloud_cloudwatch_logs:configure(?ACCESS_KEY_ID, ?SECRET_ACCESS_KEY),
            Fun()
        end
    }}.


output_tests(Fun, Tests) ->
    [output_test(Fun, Test) || Test <- Tests].


output_test(Fun, {Line, {Description, ResponseBody, Expected}}) ->
    {Description, {Line,
        fun() ->
            meck:expect(
                erlcloud_httpc,
                request,
                fun(_Url, post, _Headers, _Body, _Timeout, _Config) ->
                    {ok, {{200, "OK"}, [], ResponseBody}}
                end
            ),
            erlcloud_cloudwatch_logs:configure(?ACCESS_KEY_ID, ?SECRET_ACCESS_KEY),
            ?assertEqual(Expected, _Actual = Fun())
        end
    }}.


sort_json([{_, _} | _] = Json) ->
    Sorted = [{Key, sort_json(Value)} || {Key, Value} <- Json],
    lists:keysort(1, Sorted);
sort_json([_ | _] = Json) ->
    [sort_json(Item) || Item <- Json];
sort_json(Value) ->
    Value.
