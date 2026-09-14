import gzip
import io
import json
import sys
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

import track_request


class FakeLogsClient:
    # one response per start_query call, in order; running_polls forces that many
    # non-Complete polls first so the polling loops actually loop

    def __init__(self, responses: list[dict], running_polls: int = 0):
        self.responses = list(responses)
        self.running_polls = running_polls
        self.query_calls: list[dict] = []
        self.poll_counts: dict[str, int] = {}

    def start_query(self, **kwargs) -> dict:
        self.query_calls.append(kwargs)
        return {"queryId": f"query-{len(self.query_calls)}"}

    def get_query_results(self, queryId: str) -> dict:
        self.poll_counts[queryId] = self.poll_counts.get(queryId, 0) + 1
        if self.poll_counts[queryId] <= self.running_polls:
            return {"status": "Running"}

        return self.responses[len(self.query_calls) - 1]


def result_row(fields: dict[str, str]) -> list[dict]:
    return [{"field": name, "value": value} for name, value in fields.items()]


def base_moment() -> datetime:
    return datetime(2026, 1, 1, tzinfo=timezone.utc)


def chunked_rows(first_index: int, count: int) -> list[list[dict]]:
    # strictly increasing millisecond timestamps starting at first_index
    rows = []
    for offset in range(count):
        moment = base_moment() + timedelta(milliseconds=first_index + offset)
        rows.append(result_row({"@timestamp": moment.isoformat(), "@message": f"line-{first_index + offset}"}))
    return rows


def lambda_invocation_lines() -> list[str]:
    return [
        "Making request for OperationModel(name=Invoke) with params {'body': b'{\"claim_id\": 7}', "
        "'url': 'https://lambda.us-east-1.amazonaws.com/2015-03-31/functions/claim_worker/invocations'}",
        "https://lambda.us-east-1.amazonaws.com/2015-03-31 POST /functions/claim_worker/invocations",
        "Response headers: {'x-amzn-RequestId': 'sub-rid-42', 'Server': 'Server'}",
    ]


def batch_submit_lines() -> list[str]:
    return [
        "2026-01-01T00:00:00.000Z Making request for OperationModel(name=SubmitJob) with params "
        "{'body': b'{\"jobName\": \"nightly_etl\"}', 'url': 'https://batch.us-east-1.amazonaws.com/v1/submitjob'}",
        '{"jobId":"job-77","jobName":"nightly_etl_20260101"}',
    ]


def use_logs_client(monkeypatch, responses: list[dict], running_polls: int = 0) -> FakeLogsClient:
    fake_client = FakeLogsClient(responses, running_polls=running_polls)
    monkeypatch.setattr(
        track_request,
        "get_botocore_client",
        lambda service: fake_client,
    )
    return fake_client


def test_query_range_covers_the_requested_window(monkeypatch):
    fake_client = use_logs_client(monkeypatch, [
        {"status": "Complete", "results": []},
        {"status": "Complete", "results": []},
    ])

    before = datetime.now(timezone.utc)
    options = track_request.build_parser().parse_args(["--days", "3"])
    track_request.execute_cloudwatch_query(options, "/aws/lambda/demo", "fields @timestamp")
    after = datetime.now(timezone.utc)

    call = fake_client.query_calls[0]
    assert call["logGroupName"] == "/aws/lambda/demo"
    assert call["queryString"] == "fields @timestamp"
    assert call["limit"] == 10000
    start = datetime.fromtimestamp(call["startTime"] / 1000, timezone.utc)
    end = datetime.fromtimestamp(call["endTime"] / 1000, timezone.utc)
    # epoch millis truncate sub-second precision, so allow a little slack
    tolerance = timedelta(seconds=5)
    assert abs(start - (before - timedelta(days=3))) < tolerance
    assert abs(end - after) < tolerance

    options = track_request.build_parser().parse_args(["--days", "2026-01-01T00:00:00Z|2026-01-02T12:00:00Z"])
    track_request.execute_cloudwatch_query(options, "/aws/lambda/demo", "fields @timestamp")

    call = fake_client.query_calls[1]
    expected_start = int(datetime(2026, 1, 1, tzinfo=timezone.utc).timestamp() * 1000)
    expected_end = int(datetime(2026, 1, 2, 12, tzinfo=timezone.utc).timestamp() * 1000)
    assert call["startTime"] == expected_start
    assert call["endTime"] == expected_end

    # whitespace around the pipe is stripped; three parts are rejected
    options = track_request.build_parser().parse_args(["--days", "2026-01-01T00:00:00Z | 2026-01-02T00:00:00Z"])
    start, end = track_request.resolve_time_range(options)
    assert start == datetime(2026, 1, 1, tzinfo=timezone.utc)
    assert end == datetime(2026, 1, 2, tzinfo=timezone.utc)

    options = track_request.build_parser().parse_args(["--days", "a|b|c"])
    with pytest.raises(ValueError):
        track_request.resolve_time_range(options)


def test_fetch_request_logs_builds_the_query_and_parses_report_lines(monkeypatch):
    report_message = (
        "REPORT RequestId: rid-report\tDuration: 240.57 ms\tBilled Duration: 240 ms"
        "\tMemory Size: 512 MB\tMax Memory Used: 61 MB"
    )
    fake_client = use_logs_client(monkeypatch, [{
        "status": "Complete",
        "results": [
            result_row({"@requestId": "rid-1", "@timestamp": "2026-01-01T00:00:00.000Z", "@message": "hello"}),
            result_row({"@requestId": "rid-report", "@message": "\trid-report\tfirst line"}),
            result_row({"@requestId": "rid-report", "@message": report_message}),
        ],
    }])

    options = track_request.build_parser().parse_args([])

    logs_map = track_request.fetch_request_logs(options, "/aws/lambda/demo", ["rid-1", "rid-report"])

    expected_query = (
        "fields @requestId, @timestamp, @message"
        " | filter @requestId in ['rid-1','rid-report']"
        " | sort @timestamp asc"
    )
    assert fake_client.query_calls[0]["queryString"] == expected_query
    assert fake_client.query_calls[0]["logGroupName"] == "/aws/lambda/demo"
    assert logs_map["rid-1"]["logs"] == ["hello"]
    assert logs_map["rid-report"]["logs"] == ["first line", report_message]
    assert logs_map["rid-report"]["duration"] == 240 / 1000
    assert logs_map["rid-report"]["memsize"] == 512
    assert logs_map["rid-report"]["memused"] == 61


def test_fetch_request_logs_polls_until_all_ids_return_or_times_out(monkeypatch, caplog):
    monkeypatch.setattr(track_request.time, "sleep", lambda seconds: None)
    fake_client = use_logs_client(monkeypatch, [
        {"status": "Complete", "results": [result_row({"@requestId": "rid-1", "@message": "one"})]},
        {"status": "Complete", "results": [
            result_row({"@requestId": "rid-1", "@message": "one"}),
            result_row({"@requestId": "rid-2", "@message": "two"}),
        ]},
    ])

    options = track_request.build_parser().parse_args([])

    logs_map = track_request.fetch_request_logs(options, "/aws/lambda/demo", ["rid-1", "rid-2"])

    assert len(fake_client.query_calls) == 2
    assert set(logs_map) == {"rid-1", "rid-2"}

    use_logs_client(monkeypatch, [])
    logs_map = track_request.fetch_request_logs(options, "/aws/lambda/demo", ["rid-1"], timeout=0)

    assert logs_map == {}
    warnings = [r.getMessage() for r in caplog.records if "invalid response while fetching logs" in r.getMessage()]
    assert len(warnings) == 1


def test_fetch_batch_logs_groups_by_stream_and_measures_duration(monkeypatch):
    fake_client = use_logs_client(monkeypatch, [{
        "status": "Complete",
        "results": [
            result_row({"@logStream": "stream-1", "@message": "start line", "@timestamp": "2026-01-01T00:00:00.000Z"}),
            result_row({"@logStream": "stream-1", "@message": "end line", "@timestamp": "2026-01-01T00:00:02.500Z"}),
        ],
    }])

    options = track_request.build_parser().parse_args([])

    log_stream_logs = track_request.fetch_batch_logs(options, "stream-1")

    expected_query = (
        "fields @logStream, @timestamp, @message"
        " | filter @logStream in ['stream-1']"
        " | sort @timestamp asc"
    )
    assert fake_client.query_calls[0]["queryString"] == expected_query
    assert fake_client.query_calls[0]["logGroupName"] == "/aws/batch/job"
    assert log_stream_logs["stream-1"]["duration"] == 2500 / 1000
    assert log_stream_logs["stream-1"]["logs"] == ["start line", "end line"]


def test_chunking_walks_past_ten_thousand_result_cap(monkeypatch):
    first_rows = chunked_rows(0, 10000)
    continuation_rows = [first_rows[-1]]
    continuation_rows.extend(chunked_rows(10000, 4))
    fake_client = use_logs_client(monkeypatch, [
        {"status": "Complete", "results": first_rows},
        {"status": "Complete", "results": continuation_rows},
    ])

    options = track_request.build_parser().parse_args([])

    response = track_request.execute_cloudwatch_query(options, "/aws/lambda/demo", "fields @timestamp")

    assert response is not None
    assert len(fake_client.query_calls) == 2
    last_timestamp = base_moment() + timedelta(milliseconds=9999)
    assert fake_client.query_calls[1]["startTime"] == int(last_timestamp.timestamp() * 1000)
    # 10000 lines minus the overlap duplicate, plus the 5 continuation lines (duplicate included)
    assert len(response["results"]) == 10000 - 1 + 5
    assert response["results"][-1][1]["value"] == "line-10003"


def test_chunking_stops_after_thirty_query_passes(monkeypatch):
    responses = [{"status": "Complete", "results": chunked_rows(0, 10000)}]
    last_index = 9999
    for _pass in range(29):
        duplicate = chunked_rows(last_index, 1)[0]
        responses.append({"status": "Complete", "results": [duplicate, *chunked_rows(last_index + 1, 9999)]})
        last_index += 9999
    fake_client = use_logs_client(monkeypatch, responses)

    options = track_request.build_parser().parse_args([])

    response = track_request.execute_cloudwatch_query(options, "/aws/lambda/demo", "fields @timestamp")

    assert response is not None
    # the initial query plus 29 continuations; every pass deduplicates one overlap line
    assert len(fake_client.query_calls) == 30
    assert len(response["results"]) == 10000 + 29 * 9999


def test_chunking_stops_when_the_continuation_returns_nothing(monkeypatch, caplog):
    monkeypatch.setattr(track_request.time, "sleep", lambda seconds: None)

    options = track_request.build_parser().parse_args([])

    empty_continuation = use_logs_client(monkeypatch, [
        {"status": "Complete", "results": chunked_rows(0, 10000)},
        {"status": "Complete", "results": []},
    ])
    response = track_request.execute_cloudwatch_query(options, "/aws/lambda/demo", "fields @timestamp")

    assert response is not None
    assert len(response["results"]) == 10000
    assert len(empty_continuation.query_calls) == 2

    use_logs_client(monkeypatch, [
        {"status": "Complete", "results": chunked_rows(0, 10000)},
        {"status": "Running"},
    ])
    response = track_request.execute_cloudwatch_query(options, "/aws/lambda/demo", "fields @timestamp")

    assert response is not None
    assert len(response["results"]) == 10000
    errors = [r.getMessage() for r in caplog.records if "invalid subresponse" in r.getMessage()]
    assert len(errors) == 1


def test_limit_controls_chunking(monkeypatch):
    capped = use_logs_client(monkeypatch, [{"status": "Complete", "results": chunked_rows(0, 10000)}])

    options = track_request.build_parser().parse_args(["--limit", "5000"])

    track_request.execute_cloudwatch_query(options, "/aws/lambda/demo", "fields @timestamp")

    assert len(capped.query_calls) == 1
    assert capped.query_calls[0]["limit"] == 5000

    first_rows = chunked_rows(0, 10000)
    continuation_rows = [first_rows[-1]]
    continuation_rows.extend(chunked_rows(10000, 4))
    over_cap = use_logs_client(monkeypatch, [
        {"status": "Complete", "results": first_rows},
        {"status": "Complete", "results": continuation_rows},
    ])

    requested_limit = 10005
    options = track_request.build_parser().parse_args(["--limit", str(requested_limit)])

    response = track_request.execute_cloudwatch_query(options, "/aws/lambda/demo", "fields @timestamp")

    assert response is not None
    assert over_cap.query_calls[1]["limit"] == requested_limit - 10000
    assert len(response["results"]) == 10000 - 1 + 5


def test_query_polls_wait_for_completion(monkeypatch):
    fake_client = use_logs_client(
        monkeypatch,
        [{"status": "Complete", "results": []}],
        running_polls=1,
    )

    options = track_request.build_parser().parse_args([])

    response = track_request.execute_cloudwatch_query(options, "/aws/lambda/demo", "fields @timestamp")

    assert response is not None
    assert response["results"] == []
    assert fake_client.poll_counts["query-1"] == 2


def test_verbose_logs_the_query(monkeypatch):
    use_logs_client(monkeypatch, [{"status": "Complete", "results": []}])

    # the root logger runs at info, so debug events are dropped before caplog sees them; capture the call
    events: list = []
    monkeypatch.setattr(track_request, "logger", SimpleNamespace(
        debug=lambda message, *args: events.append((message, args)),
    ))

    options = track_request.build_parser().parse_args(["--verbose"])

    track_request.execute_cloudwatch_query(options, "/aws/lambda/demo", "fields @timestamp")

    assert events == [(
        "fetch logs log_group_name=%s query=%s",
        ("/aws/lambda/demo", "fields @timestamp"),
    )]


def test_traverse_logs_collects_lambda_invocation_and_warns_when_partial(caplog):
    options = track_request.build_parser().parse_args([])

    subrequest_map = track_request.traverse_logs(options, "/aws/lambda/api", "rid-parent", lambda_invocation_lines())

    assert subrequest_map == {
        "/aws/lambda/claim_worker": [{
            "type": "lambda",
            "log_group_name": "/aws/lambda/claim_worker",
            "request_id": "sub-rid-42",
            "invoked_by_log_group_name": "/aws/lambda/api",
            "invoked_by_request_id": "rid-parent",
            "payload": '{"claim_id": 7}',
        }],
    }

    lines = lambda_invocation_lines()[:1]
    subrequest_map = track_request.traverse_logs(options, "/aws/lambda/api", "rid-parent", lines)

    assert subrequest_map == {}
    warnings = [
        r.getMessage() for r in caplog.records
        if "unable to parse lambda invocation response" in r.getMessage()
    ]
    assert len(warnings) == 1


def test_traverse_logs_collects_batch_invocation_from_describe(stubbed_aws):
    lines = [
        "Making request for OperationModel(name=SubmitJob) with params {'body': b'{\"jobName\": \"nightly_etl\"}', "
        "'url': 'https://batch.us-east-1.amazonaws.com/v1/submitjob'}",
        '{"jobId":"job-77","jobName":"nightly_etl_20260101"}',
    ]
    job_memory = 4096
    _, stubber = stubbed_aws("batch")
    # the stub validates response shapes, so the job carries the members
    # the describe contract always returns
    job = {
        "jobId": "job-77",
        "jobName": "nightly_etl_20260101",
        "jobQueue": "nightly-queue",
        "startedAt": 1767225600000,
        "jobDefinition": "nightly-etl",
        "status": "SUCCEEDED",
        "container": {"logStreamName": "nightly_etl/default/abc", "memory": job_memory},
    }
    stubber.add_response(
        "describe_jobs",
        {"jobs": [job]},
        expected_params={"jobs": ["job-77"]},
    )

    options = track_request.build_parser().parse_args([])

    subrequest_map = track_request.traverse_logs(options, "/aws/lambda/api", "rid-parent", lines)

    entry = subrequest_map["/aws/batch/job"][0]
    assert entry["type"] == "batch"
    assert entry["job_id"] == "job-77"
    assert entry["log_stream_name"] == "nightly_etl/default/abc"
    assert entry["memsize"] == job_memory
    assert entry["memused"] == "?"
    assert entry["payload"] == '{"jobName": "nightly_etl"}'
    assert entry["invoked_by_request_id"] == "rid-parent"


def test_traverse_logs_batch_fallback_matches_stream_on_timestamps(stubbed_aws, monkeypatch, capsys):
    _, stubber = stubbed_aws("batch")
    stubber.add_response(
        "describe_jobs",
        {"jobs": []},
        expected_params={"jobs": ["job-77"]},
    )

    captured = {}

    def fake_execute(options, log_group_name, query):
        captured["log_group_name"] = log_group_name
        captured["query"] = query
        return {
            "status": "Complete",
            "results": [
                result_row({"@logStream": "nightly_etl/default/abc", "@message": "running with source version 0a1b2c"}),
                result_row({"@logStream": "nightly_etl/default/abc", "@message": "other line"}),
            ],
        }

    monkeypatch.setattr(track_request, "execute_cloudwatch_query", fake_execute)

    options = track_request.build_parser().parse_args([])

    subrequest_map = track_request.traverse_logs(options, "/aws/lambda/api", "rid-parent", batch_submit_lines())

    assert captured["log_group_name"] == "/aws/batch/job"
    window_start = track_request.to_epoch_millis(datetime(2026, 1, 1, tzinfo=timezone.utc))
    window_end = track_request.to_epoch_millis(datetime(2026, 1, 1, tzinfo=timezone.utc) + timedelta(minutes=8))
    assert "filter @logStream like 'nightly_etl'" in captured["query"]
    assert f"millis > {window_start} and millis < {window_end}" in captured["query"]

    entry = subrequest_map["/aws/batch/job"][0]
    assert entry["log_stream_name"] == "nightly_etl/default/abc"
    assert entry["memsize"] == "?"
    assert capsys.readouterr().out == ""


def test_traverse_logs_batch_fallback_skips_on_ambiguous_input(stubbed_aws, monkeypatch, caplog):
    # one describe per traverse: the ambiguous-stream pass and the
    # untimestamped pass each exhaust the describe ladder
    _, stubber = stubbed_aws("batch")
    stubber.add_response(
        "describe_jobs",
        {"jobs": []},
        expected_params={"jobs": ["job-77"]},
    )
    stubber.add_response(
        "describe_jobs",
        {"jobs": []},
        expected_params={"jobs": ["job-77"]},
    )

    def fake_execute(options, log_group_name, query):
        return {
            "status": "Complete",
            "results": [
                result_row({"@logStream": "stream-a", "@message": "running with source version 0a1b2c"}),
                result_row({"@logStream": "stream-b", "@message": "running with source version 0a1b2c"}),
            ],
        }

    monkeypatch.setattr(track_request, "execute_cloudwatch_query", fake_execute)

    options = track_request.build_parser().parse_args([])

    subrequest_map = track_request.traverse_logs(options, "/aws/lambda/api", "rid-parent", batch_submit_lines())

    assert subrequest_map == {}
    warnings = [
        r.getMessage() for r in caplog.records
        if "multiple log streams found" in r.getMessage()
    ]
    assert len(warnings) == 1

    # without a parseable timestamp the fallback never queries at all
    caplog.clear()
    untimestamped_lines = [
        "Making request for OperationModel(name=SubmitJob) with params {'body': b'{}', "
        "'url': 'https://batch.us-east-1.amazonaws.com/v1/submitjob'}",
        '{"jobId":"job-77","jobName":"nightly_etl_20260101"}',
    ]
    subrequest_map = track_request.traverse_logs(options, "/aws/lambda/api", "rid-parent", untimestamped_lines)

    assert subrequest_map == {}
    warnings = [
        r.getMessage() for r in caplog.records
        if "unable to parse timestamp" in r.getMessage()
    ]
    assert len(warnings) == 1


def test_request_graph_nests_subrequests_under_their_service(monkeypatch):
    use_logs_client(monkeypatch, [{
        "status": "Complete",
        "results": [
            result_row(
                {"@requestId": "sub-rid-42", "@message": "child did work", "@timestamp": "2026-01-01T00:00:00.000Z"},
            ),
        ],
    }])

    options = track_request.build_parser().parse_args([])

    graph = track_request.get_request_graph(options, "/aws/lambda/api", "rid-parent", lambda_invocation_lines())

    child = graph["/aws/lambda/claim_worker"]["sub-rid-42"]
    assert child["logs"] == ["child did work"]
    assert child["invoked_by_log_group_name"] == "/aws/lambda/api"
    assert child["invoked_by_request_id"] == "rid-parent"
    assert child["graph"] == {}


def test_visualize_graph_prints_summary_and_exceptions(capsys):
    options = track_request.build_parser().parse_args(
        ["--format", "{log_group_name}|{request_id}|{duration}|{errors}|{subrequests}"],
    )
    graph = {
        "/aws/lambda/api": {
            "rid-parent": {
                "duration": 1.5,
                "memsize": 512,
                "memused": 128,
                "logs": ["fine", "bad [ERROR] thing", "Exception: ValueErr: boom"],
                "graph": {
                    "/aws/lambda/child": {
                        "rid-child": {
                            "duration": None,
                            "logs": [],
                            "graph": {},
                        },
                    },
                },
            },
        },
    }

    track_request.visualize_graph(options, graph)

    output = capsys.readouterr().out
    assert "/aws/lambda/api|rid-parent" in output
    assert "1.50|1|1" in output
    assert "/aws/lambda/child|rid-child" in output
    assert "error: ValueErr: boom" in output
    assert "(1 exceptions)" in output

    # the default format renders duration, memory, and zero counts
    options = track_request.build_parser().parse_args([])
    graph = {
        "/aws/lambda/api": {
            "rid-1": {"duration": 0.5, "memsize": 512, "memused": 64, "logs": [], "graph": {}},
        },
    }

    track_request.visualize_graph(options, graph)

    output = capsys.readouterr().out
    assert "rid-1" in output
    assert "0.50s" in output
    assert "64/512 MB" in output
    assert "0 lines" in output
    assert "0 errors" in output
    assert "0 subrequests" in output


def test_save_graph_writes_logs_and_invocation_metadata(tmp_path):
    options = track_request.build_parser().parse_args([])
    graph = {
        "/aws/lambda/api": {
            "rid-parent": {
                "duration": 1.0,
                "memsize": 512,
                "memused": 64,
                "logs": ["parent log line"],
                "graph": {
                    "/aws/lambda/child": {
                        "rid-child": {
                            "duration": None,
                            "logs": ["child log line"],
                            "invoked_by_log_group_name": "/aws/lambda/api",
                            "invoked_by_request_id": "rid-parent",
                            "payload": '{"claim_id": 7}',
                            "graph": {},
                        },
                    },
                },
            },
        },
    }
    output = tmp_path / "track.log"

    with output.open("wt") as fp:
        track_request.save_graph(options, fp, graph)

    text = output.read_text()
    assert "/aws/lambda/api rid-parent (1.00s" in text
    assert "parent log line" in text
    assert "  /aws/lambda/child" in text
    assert "  INVOKED BY: /aws/lambda/api rid-parent" in text
    assert '  PAYLOAD: {"claim_id": 7}' in text
    assert "child log line" in text


def test_process_and_main_read_requests_from_stdin_json(monkeypatch, capsys):
    stdin_payload = json.dumps([{"log_group_name": "/aws/lambda/api", "request_id": "rid-1"}])
    monkeypatch.setattr(sys, "stdin", io.StringIO(stdin_payload))

    captured = {}

    def fake_track_requests(options, *requests):
        captured["requests"] = list(requests)
        return {"/aws/lambda/api": {"rid-1": {"duration": 0, "memsize": "?", "memused": "?", "logs": [], "graph": {}}}}

    monkeypatch.setattr(track_request, "track_requests", fake_track_requests)

    options = track_request.build_parser().parse_args([])

    track_request.process(options)

    assert captured["requests"] == [{"log_group_name": "/aws/lambda/api", "request_id": "rid-1"}]
    assert "/aws/lambda/api rid-1" in capsys.readouterr().out

    monkeypatch.setattr(sys, "stdin", io.StringIO(stdin_payload))
    monkeypatch.setattr(track_request, "track_requests", lambda options, *requests: {})

    assert track_request.main([]) == 0


def test_process_requires_positionals_on_a_tty(monkeypatch, caplog):
    class TtyInput(io.StringIO):

        def isatty(self) -> bool:
            return True

    monkeypatch.setattr(sys, "stdin", TtyInput(""))

    def fail_track_requests(options, *requests):
        raise AssertionError("track_requests must not run without positionals")

    monkeypatch.setattr(track_request, "track_requests", fail_track_requests)

    options = track_request.build_parser().parse_args([])

    track_request.process(options)

    errors = [
        r.getMessage() for r in caplog.records
        if "positional arguments" in r.getMessage()
    ]
    assert len(errors) == 1


def test_process_routes_output_to_gzip_file_or_split_directory(tmp_path, monkeypatch):
    stdin_payload = json.dumps([{"log_group_name": "/aws/lambda/api", "request_id": "rid-parent"}])
    monkeypatch.setattr(sys, "stdin", io.StringIO(stdin_payload))

    flat_graph = {"/aws/lambda/api": {
        "rid-1": {"duration": 0, "memsize": "?", "memused": "?", "logs": ["gz line"], "graph": {}},
    }}
    monkeypatch.setattr(track_request, "track_requests", lambda options, *requests: flat_graph)

    gzip_output = tmp_path / "track.log.gz"
    options = track_request.build_parser().parse_args(["--output", str(gzip_output)])

    track_request.process(options)

    with gzip.open(gzip_output, "rt") as fp:
        assert "gz line" in fp.read()

    monkeypatch.setattr(sys, "stdin", io.StringIO(stdin_payload))
    nested_graph = {
        "/aws/lambda/api": {
            "rid-parent": {
                "duration": 0,
                "memsize": "?",
                "memused": "?",
                "logs": ["parent log line"],
                "graph": {
                    "/aws/lambda/child": {
                        "rid-child": {
                            "duration": None,
                            "logs": ["child log line"],
                            "invoked_by_log_group_name": "/aws/lambda/api",
                            "invoked_by_request_id": "rid-parent",
                            "graph": {},
                        },
                    },
                },
            },
        },
    }
    monkeypatch.setattr(track_request, "track_requests", lambda options, *requests: nested_graph)

    split_directory = tmp_path / "split"
    options = track_request.build_parser().parse_args(["--output", f"log-group:{split_directory}"])

    track_request.process(options)

    parent_file = split_directory / "-aws-lambda-api.log"
    child_file = split_directory / "-aws-lambda-child.log"
    assert "parent log line" in parent_file.read_text()
    assert "INVOKED BY: /aws/lambda/api rid-parent" in child_file.read_text()
    assert "child log line" in child_file.read_text()


def test_argument_defaults():
    options = track_request.build_parser().parse_args(["/aws/lambda/demo", "rid-1"])

    assert options.log_group_name == "/aws/lambda/demo"
    assert options.request_id == "rid-1"
    assert options.days == "7"
    assert options.limit == 0
    assert options.maxdepth == 10
    assert options.verbose is False
    assert options.output is None
    assert "{log_group_name} {request_id} ({duration}s" in options.format
