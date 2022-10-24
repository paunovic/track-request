#!/usr/bin/env python

import argparse
import gzip
import os
import re
import time
from collections import defaultdict
from decimal import Decimal
from pathlib import Path
from typing import Any, List, Optional, Set

import arrow
import botocore.session


def get_botocore_client(service: str) -> Any:
    client_config: dict = {
        "aws_access_key_id": os.environ.get("AWS_ACCESS_KEY_ID"),
        "aws_secret_access_key": os.environ.get("AWS_SECRET_ACCESS_KEY"),
        "aws_session_token": os.environ.get("AWS_SESSION_TOKEN"),
    }
    client_config = {k: v for k, v in client_config.items() if v is not None}
    bs = botocore.session.get_session()
    client = bs.create_client(service_name=service, **client_config)
    return client


def parse_timestamp(line: str) -> Optional[arrow.Arrow]:
    if match := re.search(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z)", line):
        return arrow.get(match.group(1))
    else:
        return None


def parse_cloudwatch_result(result: dict, *keys: str) -> tuple:
    ret = tuple()
    for key in keys:
        value = None
        for field in result:
            if field["field"] == key:
                value = field["value"]
                break
        ret = (*ret, value)
    return ret


def execute_cloudwatch_query(log_group_name: str, query: str) -> Optional[dict]:
    if args.verbose:
        print(f"fetch logs for {log_group_name}: {query}")

    try:
        days_offset = int(args.days)
        start_time = arrow.utcnow().shift(days=-days_offset)
        end_time = arrow.utcnow()
    except ValueError:
        start_time, end_time = args.days.split("|")
        start_time = arrow.get(start_time.strip())
        end_time = arrow.get(end_time.strip())

    cloudwatch_client = get_botocore_client("logs")

    response: Optional[dict] = None
    start_query_response = cloudwatch_client.start_query(
        logGroupName=log_group_name,
        queryString=query,
        startTime=int(start_time.datetime.timestamp() * 1000),
        endTime=int(end_time.datetime.timestamp()) * 1000,
        limit=min(args.limit or 10000, 10000),
    )
    query_id: str = start_query_response["queryId"]

    # wait for query to complete
    for _ in range(30):
        response = cloudwatch_client.get_query_results(queryId=query_id)
        if response and response["status"] == "Complete":
            break
        time.sleep(2)

    # if there are more than 10k results, which is maximum per aws cloudwatch query,
    # chunk query on timestamp to retrieve all logs
    if (not args.limit or args.limit > 10000) and len(response["results"]) == 10000:
        for iteration in range(1, 30):  # fetch 30*10k=300k lines max
            # find last timestamp in logs
            timestamp_str: str = parse_cloudwatch_result(response["results"][-1], "@timestamp")[0]
            last_timestamp: arrow.Arrow = arrow.get(timestamp_str)

            limit = min(args.limit - len(response["results"]), 10000) if args.limit else 10000
            if limit <= 0:
                break

            if args.verbose:
                print(f"fetch logs for {log_group_name} ({iteration}): {query}")

            # query logs from last_timestamp
            subresponse: Optional[dict] = None
            start_query_response = cloudwatch_client.start_query(
                logGroupName=log_group_name,
                queryString=query,
                startTime=int(last_timestamp.datetime.timestamp() * 1000),
                endTime=int(end_time.datetime.timestamp()) * 1000,
                limit=limit,
            )
            query_id = start_query_response["queryId"]

            # wait for query to complete
            for _ in range(30):
                subresponse = cloudwatch_client.get_query_results(queryId=query_id)
                if subresponse and subresponse["status"] == "Complete":
                    break
                time.sleep(2)

            if not subresponse or "results" not in subresponse:
                print(f"invalid subresponse: {subresponse}")
                break

            if not subresponse["results"]:
                break

            # eliminate duplicate lines that are caused by overlapping queries
            new_timestamp_str, new_message = parse_cloudwatch_result(subresponse["results"][0], "@timestamp", "@message")
            new_timestamp: arrow.Arrow = arrow.get(new_timestamp_str)
            index = len(response["results"]) - 1
            timestamp = None
            while not timestamp or arrow.get(timestamp) >= new_timestamp:
                timestamp = parse_cloudwatch_result(response["results"][index], "@timestamp")[0]
                index -= 1
            while index < len(response["results"]) - 1:
                index += 1
                timestamp, message = parse_cloudwatch_result(response["results"][index], "@timestamp", "@message")
                if timestamp == new_timestamp_str and message == new_message:
                    break
            response["results"] = response["results"][:index]

            # merge results from subresponse to main response
            response["results"].extend(subresponse["results"])

            # stop querying if there are less than 10k results
            if len(subresponse["results"]) < 10000:
                break

            # stop querying if we fetched enough logs
            if args.limit and len(response["results"]) >= args.limit:
                break

    return response


def fetch_request_logs(log_group_name: str, request_ids: List[str], *, timeout: int = 60) -> dict:
    # fetch request logs from cloudwatch

    request_logs_map: dict = {}

    # request ids are queried in batches to avoid hitting 1000 char limit aws query constraint
    batch_size: int = 10

    # batch queries
    for start in range(0, len(request_ids), batch_size):
        response = None
        request_ids_batch: List[str] = request_ids[start:start + batch_size]
        start_time = time.perf_counter()
        while request_ids_batch and time.perf_counter() - start_time < timeout:
            query: str = (
                "fields @requestId, @timestamp, @message"
                " | filter @requestId in [{}]"
                " | sort @timestamp asc"
            ).format(",".join(f"'{r}'" for r in request_ids_batch))
            response = execute_cloudwatch_query(log_group_name, query)

            # process results
            if isinstance(response, dict) and response.get("results"):  # type: ignore
                request_id_results: Set[str] = set()
                for result in response["results"]:
                    for field in result:
                        if field["field"] == "@requestId":
                            request_id_results.add(field["value"])
                            break

                if request_id_results == set(request_ids_batch):
                    break
            else:
                if args.verbose:
                    print(response)

            time.sleep(3)

        # all subsequent fetches have 30 seconds timeout
        if timeout > 30:
            timeout = 30

        # if there are no results, continue
        if not response or not response["results"]:
            print(f"warning: invalid response while fetching logs: {response!r}")
            continue

        # parse logs
        for result in response["results"]:  # type: ignore
            request_id, message = parse_cloudwatch_result(result, "@requestId", "@message")
            if request_id and message:
                message = message.replace(f"\t{request_id}\t", "  ").strip(" \n")
                if request_id not in request_logs_map:
                    request_logs_map[request_id] = {
                        "logs": [],
                    }
                request_logs_map[request_id]["logs"].append(message)
                end_report_regex: str = (
                    fr"REPORT RequestId: {request_id}\tDuration: (.*?) ms\tBilled Duration: (.*?) ms"
                    "\tMemory Size: (.*?) MB.*?Max Memory Used: (.*?) MB"
                )
                if match := re.search(end_report_regex, message):
                    request_logs_map[request_id]["duration"] = int(match.group(2)) / 1000
                    request_logs_map[request_id]["memsize"] = int(match.group(3))
                    request_logs_map[request_id]["memused"] = int(match.group(4))
            else:
                print(f"warning: unable to parse record {result}")

    return request_logs_map


def fetch_batch_logs(*log_stream_names: str, timeout: int = 60) -> dict:
    # fetch batch logs from cloudwatch

    log_stream_names = list(log_stream_names)

    log_stream_logs: dict = {}

    # log streams are queried in batches to avoid hitting 1000 char limit aws query constraint
    batch_size: int = 10

    # batch queries
    for start in range(0, len(log_stream_names), batch_size):
        response = None
        log_stream_names_batch: List[str] = log_stream_names[start:start + batch_size]
        start_time = time.perf_counter()
        while log_stream_names_batch and time.perf_counter() - start_time < timeout:
            query: str = (
                "fields @logStream, @timestamp, @message"
                " | filter @logStream in [{}]"
                " | sort @timestamp asc"
            ).format(",".join(f"'{r}'" for r in log_stream_names_batch))
            response = execute_cloudwatch_query("/aws/batch/job", query)

            # process results
            if isinstance(response, dict) and response.get("results"):  # type: ignore
                log_stream_results: Set[str] = set()
                for result in response["results"]:
                    for field in result:
                        if field["field"] == "@logStream":
                            log_stream_results.add(field["value"])
                            break

                if log_stream_results == set(log_stream_names_batch):
                    break
            else:
                if args.verbose:
                    print(response)

            time.sleep(3)

        # all subsequent fetches have 30 seconds timeout
        if timeout > 30:
            timeout = 30

        # if there are no results, continue
        if not response or not response["results"]:
            print(f"warning: invalid response while fetching logs: {response!r}")
            continue

        # parse logs
        for result in response["results"]:  # type: ignore
            log_stream_name, message, timestamp = parse_cloudwatch_result(result, "@logStream", "@message", "@timestamp")
            if log_stream_name and message and timestamp:
                message = message.strip(" \n")
                if log_stream_name not in log_stream_logs:
                    log_stream_logs[log_stream_name] = {
                        "logs": [],
                        "start_time": timestamp,
                    }
                log_stream_logs[log_stream_name]["logs"].append(message)
                log_stream_logs[log_stream_name]["end_time"] = timestamp
            else:
                print(f"warning: unable to parse record {result}")

    for log_stream_name, log_stream_info in log_stream_logs.items():
        log_stream_info["duration"] = (
            arrow.get(log_stream_info["end_time"])
            - arrow.get(log_stream_info["start_time"])
        ).total_seconds()

    return log_stream_logs


def traverse_logs(log_group_name: str, request_id: str, lines: List[str]) -> dict:
    log_group_subrequest_map: dict = defaultdict(list)

    lambda_regex: re.Pattern = re.compile(
        r"Making request for OperationModel\(name=Invoke\) with params.*?'body': b'(.*?)',.*?'url': 'https://lambda.*?/functions/(\w+)/invocations")
    batch_regex: re.Pattern = re.compile(
        r"Making request for OperationModel\(name=SubmitJob\) with params.*?'body': b'(.*?)',.*?'url': 'https://batch.*?/v1/submitjob")

    # traverse logs
    for index, line in enumerate(lines):

        # parse lambda invocations
        if match := lambda_regex.search(line):
            payload: str = match.group(1)
            lambda_name: str = match.group(2)
            sublog_group_name: str = f"/aws/lambda/{lambda_name}"
            next_line: bool = False
            for subline in lines[index + 1:][:100]:
                if next_line:
                    if match := re.search(r"Response headers: .*RequestId': '([a-zA-Z\d-]+)'", subline):
                        subrequest_id: str = match.group(1)
                        log_group_subrequest_map[sublog_group_name].append({
                            "type": "lambda",
                            "log_group_name": sublog_group_name,
                            "request_id": subrequest_id,
                            "invoked_by_log_group_name": log_group_name,
                            "invoked_by_request_id": request_id,
                            "payload": payload,
                        })
                        break
                next_line: bool = bool(re.search(fr"lambda.*?amazonaws\.com.*?POST.*?/functions/{lambda_name}/invocations", subline))
            else:
                print(f"warning: cant parse lambda invocation response for {line}")
                break

        # parse batch invocations
        if match := batch_regex.search(line):
            body: str = match.group(1)
            sublog_group_name: str = f"/aws/batch/job"
            last_timestamp: Optional[arrow.Arrow] = parse_timestamp(line)
            for subline in lines[index + 1:][:100]:
                if not (match := re.search(r'"jobId":"([a-zA-Z\d-]+)"', subline)):
                    continue

                job_id: str = match.group(1)
                batch_client = get_botocore_client("batch")

                # describe batch job
                response = None
                for _ in range(120):
                    response = batch_client.describe_jobs(jobs=[job_id])
                    if not response.get("jobs"):
                        break
                    if (
                        response["jobs"][0]["container"].get("logStreamName")
                        and response["jobs"][0]["status"] in ("SUCCEEDED", "FAILED")
                    ):
                        break
                    time.sleep(2)

                if isinstance(response, dict) and response.get("jobs"):
                    log_group_subrequest_map[sublog_group_name].append({
                        "type": "batch",
                        "job_id": job_id,
                        "log_stream_name": response["jobs"][0]["container"]["logStreamName"],
                        "memused": "?",
                        "memsize": response["jobs"][0]["container"]["memory"],
                        "invoked_by_log_group_name": log_group_name,
                        "invoked_by_request_id": request_id,
                        "payload": body,
                    })
                    break

                # fallback method where we attempt to find batch log stream based on timestamps
                if args.verbose:
                    print(f"cant describe batch job {job_id}, trying to match logs on timestamps")

                if not last_timestamp:
                    print(f"warning: unable to parse timestamp: {line=}")
                    break

                job_name: str = re.search(r'"jobName":"(\w+)"', subline).group(1)
                job_name = re.search(r"^(.*)_\d+$", job_name).group(1)

                query: str = (
                    "fields @logStream, @timestamp, @message, tomillis(@timestamp) as millis"
                    " | filter @logStream like '{}'"
                    " | filter millis > {} and millis < {}"
                    " | sort @timestamp asc"
                ).format(
                    job_name,
                    int(last_timestamp.datetime.timestamp() * 1000),
                    int(last_timestamp.shift(minutes=8).datetime.timestamp() * 1000),
                )
                response = execute_cloudwatch_query("/aws/batch/job", query)
                if not response or not response["results"]:
                    print(f"warning: no batch logs found, response: {response!r}")
                    break

                # find all log stream names
                log_streams: Set[str] = set()
                for result in response["results"]:  # type: ignore
                    origin_line: bool = False
                    log_stream: str = ""
                    for field in result:
                        if field["field"] == "@message":
                            if "running with source version" in field["value"]:
                                origin_line = True
                        elif field["field"] == "@logStream":
                            log_stream = field["value"]
                    if origin_line:
                        log_streams.add(log_stream)

                # we probably have a match if only one log stream is found
                if len(log_streams) == 1:
                    log_group_subrequest_map[sublog_group_name].append({
                        "type": "batch",
                        "job_id": job_id,
                        "log_stream_name": next(iter(log_streams)),
                        "memused": "?",
                        "memsize": "?",
                        "invoked_by_log_group_name": log_group_name,
                        "invoked_by_request_id": request_id,
                        "payload": body,
                    })
                else:
                    print(f"warning: multiple log streams found for time interval {last_timestamp}+8mins: {log_streams}")

                break
            else:
                print(f"warning: cant parse batch invocation response for {line}")
                break

    return log_group_subrequest_map


def get_request_graph(log_group_name: str, request_id: str, lines: List[str], *, maxdepth: int = 1) -> dict:
    graph: dict = defaultdict(dict)

    log_group_subrequest_map: dict = traverse_logs(log_group_name, request_id, lines)

    # query logs for each subrequest group
    for log_subgroup_name, log_group_subrequests in log_group_subrequest_map.items():

        # fetch logs
        if log_group_subrequests[0]["type"] == "lambda":
            subrequest_key = "request_id"
            subrequest_ids = [r[subrequest_key] for r in log_group_subrequests]
            subrequest_logs_map = fetch_request_logs(log_subgroup_name, subrequest_ids)
        elif log_group_subrequests[0]["type"] == "batch":
            subrequest_key = "log_stream_name"
            subrequest_ids = [r[subrequest_key] for r in log_group_subrequests]
            subrequest_logs_map = fetch_batch_logs(*subrequest_ids)
        else:
            raise Exception(f"Implementation Error - unknown subrequest type {log_group_subrequests}")

        # insert new nodes into graph and traverse deeper
        for subrequest_id in subrequest_ids:
            for r in log_group_subrequests:
                if r[subrequest_key] == subrequest_id:
                    subrequest_info = r
                    break
            else:
                print(f"implementation error: {subrequest_id} not found in {log_group_subrequests!r}")
                continue

            subrequest_logs: dict = subrequest_logs_map.get(subrequest_id, {})

            graph[log_subgroup_name][subrequest_id] = {
                **subrequest_info,
                **subrequest_logs,
                "graph": {},
            }

            if maxdepth != 1:
                graph[log_subgroup_name][subrequest_id]["graph"] = get_request_graph(
                    log_subgroup_name,
                    subrequest_id,
                    maxdepth=maxdepth - 1,
                    lines=subrequest_logs.get("logs", []),
                )

    return graph


def track_requests(*requests: dict) -> dict:
    log_groups: dict = defaultdict(dict)
    for request in requests:
        if request["request_id"] not in log_groups[request["log_group_name"]]:
            log_groups[request["log_group_name"]][request["request_id"]] = request

    graph: dict = defaultdict(dict)
    for log_group_name, request_list in log_groups.items():
        if log_group_name == "/aws/batch/job":
            request_logs = fetch_batch_logs(*list(request_list.keys()), timeout=240)
        else:
            request_logs = fetch_request_logs(log_group_name, list(request_list.keys()), timeout=240)

        for request_id in request_list:
            graph[log_group_name][request_id] = {
                **request_logs.get(request_id, {"logs": []}),
                **request_list[request_id],
                "graph": get_request_graph(
                    log_group_name,
                    request_id,
                    lines=request_logs.get(request_id, {}).get("logs", []),
                    maxdepth=args.maxdepth,
                ),
            }

    return graph


def visualize_graph(graph: dict, *, level: int = 0) -> None:
    try:
        maxwidth, _ = os.get_terminal_size()
    except OSError:
        maxwidth = 160

    indent: str = " " * level * 2
    for log_group_name, requests in graph.items():
        for request_id, request_info in requests.items():
            errors: int = 0
            exceptions: List[str] = []
            for line in request_info.get("logs", []):
                if "[ERROR]" in line:
                    errors += 1
                if "[ERROR]" and "Exception:" in line:
                    if match := re.search(r"Exception: (.*?)$", line):
                        exceptions.append(match.group(1).strip())

            subrequests_count: int = len(request_info["graph"])

            line = indent + args.format.format(
                request_id=request_id,
                log_group_name=log_group_name,
                duration=Decimal(request_info.get("duration") or 0).quantize(Decimal("0.01")),
                memused=request_info.get("memused"),
                memsize=request_info.get("memsize"),
                logcount=len(request_info.get("logs", [])),
                errors=errors,
                subrequests=subrequests_count,
            )
            print(line)

            # print exceptions
            if exceptions:
                for exception in exceptions[:3]:
                    if len(exception) + len(indent) > maxwidth - 12:
                        exception = exception[:maxwidth - len(indent) - 12] + "..."
                    print(indent + "  error: " + exception)
                print(indent + f"  ({len(exceptions)} exceptions)")

            visualize_graph(request_info["graph"], level=level + 1)


def save_graph(fp: Any, graph: dict, *, level: int = 0) -> None:
    indent: str = " " * level * 2
    for log_group_name, requests in graph.items():
        for request_id, request_info in requests.items():
            errors: int = 0
            for line in request_info["logs"]:
                if "[ERROR]" in line:
                    errors += 1

            subrequests_count: int = len(request_info["graph"])

            line = indent + args.format.format(
                request_id=request_id,
                log_group_name=log_group_name,
                duration=Decimal(request_info.get("duration") or 0).quantize(Decimal("0.01")),
                memused=request_info.get("memused"),
                memsize=request_info.get("memsize"),
                logcount=len(request_info["logs"]),
                errors=errors,
                subrequests=subrequests_count,
            )
            fp.write(line + "\n")

            if "invoked_by_log_group_name" in request_info:
                fp.write(indent + "INVOKED BY: {} {}\n".format(
                    request_info["invoked_by_log_group_name"],
                    request_info["invoked_by_request_id"],
                ))

            if url := request_info.get("url"):
                fp.write(indent + "URL: " + url + "\n")

            if payload := request_info.get("payload"):
                fp.write(indent + "PAYLOAD: " + payload + "\n")

            for line in request_info["logs"]:
                fp.write(indent + line + "\n")

            fp.write("\n")

            save_graph(fp, request_info["graph"], level=level + 1)


def save_graph_split_per_log_group(graph: dict, directory: Path) -> None:
    for log_group_name, requests in graph.items():
        with directory.joinpath(log_group_name.replace("/", "-")).with_suffix(".log").open("a+") as fp:
            for request_id, request in requests.items():
                errors: int = 0
                for line in request.get("logs", []):
                    if "[ERROR]" in line:
                        errors += 1

                subrequests_count: int = len(request["graph"])

                line = "{log_group_name} {request_id} ({duration}s, {memused}/{memsize} MB, {logcount} lines, {errors} errors, {subrequests} subrequests)".format(
                    request_id=request_id,
                    log_group_name=log_group_name,
                    duration=Decimal(request.get("duration") or 0).quantize(Decimal("0.01")),
                    memused=request.get("memused"),
                    memsize=request.get("memsize"),
                    logcount=len(request.get("logs", [])),
                    errors=errors,
                    subrequests=subrequests_count,
                )
                fp.write(line + "\n")

                if "invoked_by_log_group_name" in request:
                    fp.write("INVOKED BY: {} {}\n".format(
                        request["invoked_by_log_group_name"],
                        request["invoked_by_request_id"],
                    ))

                if url := request.get("url"):
                    fp.write("URL: " + url + "\n")

                if payload := request.get("payload"):
                    fp.write("PAYLOAD: " + payload + "\n")

                for line in request.get("logs", []):
                    fp.write(line + "\n")

                fp.write("\n")

    for log_group_name, requests in graph.items():
        for request in requests.values():
            save_graph_split_per_log_group(request["graph"], directory)


def process() -> None:
    graph = track_requests({
        "log_group_name": args.log_group_name,
        "request_id": args.request_id,
    })

    visualize_graph(graph)

    if args.output:
        if args.output.lower().endswith(".gz"):
            with gzip.open(args.output, "wt") as gfp:
                save_graph(gfp, graph)

        elif args.output.startswith("log-group:"):
            directory: Path = Path(args.output[10:])
            directory.mkdir(parents=True, exist_ok=True)
            save_graph_split_per_log_group(graph, directory)

        else:
            with open(args.output, "w") as fp:
                save_graph(fp, graph)
                fp.truncate()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "log_group_name",
        type=str,
    )
    parser.add_argument(
        "request_id",
        type=str,
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Verbose mode.",
    )
    parser.add_argument(
        "-f",
        "--format",
        type=str,
        default="{log_group_name} {request_id} ({duration}s, {memused}/{memsize} MB, {logcount} lines, {errors} errors, {subrequests} subrequests)",
        help="Output format.",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=str,
        default=None,
        help="Output file.",
    )
    parser.add_argument(
        "-d",
        "--days",
        type=str,
        default="7",
        help="Number of days to look back for logs, or time range in `start_time|end_time` format.",
    )
    parser.add_argument(
        "-l",
        "--limit",
        type=int,
        default=0,
        help="Maximum number of log lines to fetch per request.",
    )
    parser.add_argument(
        "-m",
        "--maxdepth",
        type=int,
        default=10,
        help="Maximum log traversal depth. 0 for unlimited.",
    )
    args = parser.parse_args()

    process()
