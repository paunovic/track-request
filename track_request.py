#!/usr/bin/env python

import argparse
import gzip
import json
import logging
import os
import re
import sys
import time
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from pathlib import Path
from typing import Any

import botocore.session

logger = logging.getLogger(__name__)


def get_botocore_client(service: str) -> Any:
    # the session resolves credentials through its own chain: env
    # vars, profiles, whatever the ambient aws setup provides
    return botocore.session.get_session().create_client(service_name=service)


def parse_iso_timestamp(value: str) -> datetime:
    parsed: datetime = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def to_epoch_millis(moment: datetime) -> int:
    return int(moment.timestamp() * 1000)


def parse_timestamp(line: str) -> datetime | None:
    if match := re.search(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z)", line):
        return parse_iso_timestamp(match.group(1))
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


def resolve_time_range(options: argparse.Namespace) -> tuple[datetime, datetime]:
    try:
        days_offset = int(options.days)
    except ValueError:
        start_text, end_text = options.days.split("|")
        return parse_iso_timestamp(start_text.strip()), parse_iso_timestamp(end_text.strip())

    # naive inputs read as utc
    now = datetime.now(timezone.utc)
    return now - timedelta(days=days_offset), now


# the poll/retry ladder reads better as one straight-line function than
# split across helpers
def execute_cloudwatch_query(options: argparse.Namespace, log_group_name: str, query: str) -> dict | None:
    if options.verbose:
        logger.debug("fetch logs log_group_name=%s query=%s", log_group_name, query)

    start_time, end_time = resolve_time_range(options)

    # aws caps one insights query at 10k results
    query_result_cap: int = 10000

    cloudwatch_client = get_botocore_client("logs")

    # starts as an empty dict so a never-completing query still has a shape to return
    response: dict = {}
    start_query_response = cloudwatch_client.start_query(
        logGroupName=log_group_name,
        queryString=query,
        startTime=to_epoch_millis(start_time),
        endTime=to_epoch_millis(end_time),
        limit=min(options.limit or query_result_cap, query_result_cap),
    )
    query_id: str = start_query_response["queryId"]

    # wait for query to complete
    for _ in range(30):
        response = cloudwatch_client.get_query_results(queryId=query_id)
        if response and response["status"] == "Complete":
            break
        time.sleep(2)

    # chunk on timestamp to retrieve logs past the result cap
    if (
        (not options.limit or options.limit > query_result_cap)
        and len(response["results"]) == query_result_cap
    ):
        for iteration in range(1, 30):  # fetch 30*10k=300k lines max
            # find last timestamp in logs
            timestamp_str: str = parse_cloudwatch_result(response["results"][-1], "@timestamp")[0]
            last_timestamp: datetime = parse_iso_timestamp(timestamp_str)

            limit = min(options.limit - len(response["results"]), query_result_cap) if options.limit else query_result_cap
            if limit <= 0:
                break

            if options.verbose:
                logger.debug(
                    "fetch logs continuation log_group_name=%s iteration=%s query=%s",
                    log_group_name,
                    iteration,
                    query,
                )

            # query logs from last_timestamp
            subresponse: dict = {}
            start_query_response = cloudwatch_client.start_query(
                logGroupName=log_group_name,
                queryString=query,
                startTime=to_epoch_millis(last_timestamp),
                endTime=to_epoch_millis(end_time),
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
                logger.error("invalid subresponse: %r", subresponse)
                break

            if not subresponse["results"]:
                break

            # eliminate duplicate lines that are caused by overlapping queries
            new_timestamp_str, new_message = parse_cloudwatch_result(subresponse["results"][0], "@timestamp", "@message")
            new_timestamp: datetime = parse_iso_timestamp(new_timestamp_str)
            index = len(response["results"]) - 1
            timestamp = None
            while not timestamp or parse_iso_timestamp(timestamp) >= new_timestamp:
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
            if len(subresponse["results"]) < query_result_cap:
                break

            # stop querying if we fetched enough logs
            if options.limit and len(response["results"]) >= options.limit:
                break

    return response


def fetch_request_logs(options: argparse.Namespace, log_group_name: str, request_ids: list[str], *, timeout: int = 60) -> dict:
    # fetch request logs from cloudwatch

    request_logs_map: dict = {}

    # request ids are queried in batches to avoid hitting 1000 char limit aws query constraint
    batch_size: int = 10

    # batch queries
    for start in range(0, len(request_ids), batch_size):
        response = None
        request_ids_batch: list[str] = request_ids[start:start + batch_size]
        start_time: float = time.perf_counter()
        while request_ids_batch and time.perf_counter() - start_time < timeout:
            query: str = (
                "fields @requestId, @timestamp, @message"
                " | filter @requestId in [{}]"
                " | sort @timestamp asc"
            ).format(",".join(f"'{request_id}'" for request_id in request_ids_batch))
            response = execute_cloudwatch_query(options, log_group_name, query)

            # process results
            if isinstance(response, dict) and response.get("results"):
                request_id_results: set[str] = set()
                for result in response["results"]:
                    for field in result:
                        if field["field"] == "@requestId":
                            request_id_results.add(field["value"])
                            break

                if request_id_results == set(request_ids_batch):
                    break
            elif options.verbose:
                logger.debug("query response: %r", response)

            time.sleep(3)

        # all subsequent fetches have 30 seconds timeout
        timeout = min(timeout, 30)

        # if there are no results, continue
        if not response or not response["results"]:
            logger.warning("invalid response while fetching logs: %r", response)
            continue

        # parse logs
        for result in response["results"]:
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
                logger.warning("unable to parse record: %r", result)

    return request_logs_map


def fetch_batch_logs(options: argparse.Namespace, *log_stream_names: str, timeout: int = 60) -> dict:
    # fetch batch logs from cloudwatch

    stream_names: list[str] = list(log_stream_names)

    log_stream_logs: dict = {}

    # log streams are queried in batches to avoid hitting 1000 char limit aws query constraint
    batch_size: int = 10

    # batch queries
    for start in range(0, len(stream_names), batch_size):
        response = None
        log_stream_names_batch: list[str] = stream_names[start:start + batch_size]
        start_time: float = time.perf_counter()
        while log_stream_names_batch and time.perf_counter() - start_time < timeout:
            query: str = (
                "fields @logStream, @timestamp, @message"
                " | filter @logStream in [{}]"
                " | sort @timestamp asc"
            ).format(",".join(f"'{log_stream_name}'" for log_stream_name in log_stream_names_batch))
            response = execute_cloudwatch_query(options, "/aws/batch/job", query)

            # process results
            if isinstance(response, dict) and response.get("results"):
                log_stream_results: set[str] = set()
                for result in response["results"]:
                    for field in result:
                        if field["field"] == "@logStream":
                            log_stream_results.add(field["value"])
                            break

                if log_stream_results == set(log_stream_names_batch):
                    break
            elif options.verbose:
                logger.debug("query response: %r", response)

            time.sleep(3)

        # all subsequent fetches have 30 seconds timeout
        timeout = min(timeout, 30)

        # if there are no results, continue
        if not response or not response["results"]:
            logger.warning("invalid response while fetching logs: %r", response)
            continue

        # parse logs
        for result in response["results"]:
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
                logger.warning("unable to parse record: %r", result)

    for log_stream_name, log_stream_info in log_stream_logs.items():
        log_stream_info["duration"] = (
            parse_iso_timestamp(log_stream_info["end_time"])
            - parse_iso_timestamp(log_stream_info["start_time"])
        ).total_seconds()

    return log_stream_logs


def collect_lambda_invocation(
    match: re.Match,
    log_group_name: str,
    request_id: str,
    lines: list[str],
    index: int,
    log_group_subrequest_map: defaultdict,
) -> bool:
    # returns False when the response line cannot be parsed and traversal must stop

    payload: str = match.group(1)
    lambda_name: str = match.group(2)
    sublog_group_name: str = f"/aws/lambda/{lambda_name}"
    next_line: bool = False
    for subline in lines[index + 1:][:100]:
        if next_line:
            if header_match := re.search(r"Response headers: .*RequestId': '([a-zA-Z\d-]+)'", subline):
                subrequest_id: str = header_match.group(1)
                log_group_subrequest_map[sublog_group_name].append({
                    "type": "lambda",
                    "log_group_name": sublog_group_name,
                    "request_id": subrequest_id,
                    "invoked_by_log_group_name": log_group_name,
                    "invoked_by_request_id": request_id,
                    "payload": payload,
                })
                return True
        next_line = bool(
            re.search(fr"lambda.*?amazonaws\.com.*?POST.*?/functions/{lambda_name}/invocations", subline),
        )
    logger.warning("unable to parse lambda invocation response: %s", lines[index])
    return False


# the batch-invocation parser walks one log record shape; splitting it would hide the
# record's field sequence it mirrors
def collect_batch_invocation(
    match: re.Match,
    options: argparse.Namespace,
    log_group_name: str,
    request_id: str,
    lines: list[str],
    index: int,
    log_group_subrequest_map: defaultdict,
) -> bool:
    # returns False when the response line cannot be parsed and traversal must stop

    body: str = match.group(1)
    sublog_group_name: str = "/aws/batch/job"
    last_timestamp: datetime | None = parse_timestamp(lines[index])
    for subline in lines[index + 1:][:100]:
        if not (job_id_match := re.search(r'"jobId":"([a-zA-Z\d-]+)"', subline)):
            continue

        job_id: str = job_id_match.group(1)
        batch_client = get_botocore_client("batch")

        # describe batch job
        response: dict = {}
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
            return True

        # fallback method where we attempt to find batch log stream based on timestamps
        if options.verbose:
            logger.debug(
                "unable to describe batch job, matching logs on timestamps job_id=%s",
                job_id,
            )

        if not last_timestamp:
            logger.warning("unable to parse timestamp: %s", lines[index])
            return True

        job_name_match: re.Match[str] | None = re.search(r'"jobName":"(\w+)"', subline)
        undated_name_match = re.search(r"^(.*)_\d+$", job_name_match.group(1)) if job_name_match else None
        if undated_name_match is None:
            logger.warning("unable to parse job name: %s", subline)
            return True
        job_name: str = undated_name_match.group(1)

        query: str = (
            "fields @logStream, @timestamp, @message, tomillis(@timestamp) as millis"
            " | filter @logStream like '{}'"
            " | filter millis > {} and millis < {}"
            " | sort @timestamp asc"
        ).format(
            job_name,
            to_epoch_millis(last_timestamp),
            to_epoch_millis(last_timestamp + timedelta(minutes=8)),
        )
        logs_response: dict | None = execute_cloudwatch_query(options, "/aws/batch/job", query)
        if not logs_response or not logs_response["results"]:
            logger.warning("no batch logs found: %r", logs_response)
            return True

        # find all log stream names
        log_streams: set[str] = set()
        for result in logs_response["results"]:
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
            logger.warning(
                "multiple log streams found for time interval:"
                " interval_start=%s log_streams=%r",
                str(last_timestamp),
                sorted(log_streams),
            )

        return True
    logger.warning("unable to parse batch invocation response: %s", lines[index])
    return False


def traverse_logs(options: argparse.Namespace, log_group_name: str, request_id: str, lines: list[str]) -> dict:
    log_group_subrequest_map: defaultdict = defaultdict(list)

    # traverse logs
    for index, line in enumerate(lines):
        # parse lambda invocations
        if match := re.search(
            r"Making request for OperationModel\(name=Invoke\) "
            r"with params.*?'body': b'(.*?)', "
            r"'url': 'https://lambda.*?/functions/(\w+)/invocations",
            line,
        ):
            if not collect_lambda_invocation(match, log_group_name, request_id, lines, index, log_group_subrequest_map):
                break

        # parse batch invocations
        if match := re.search(
            r"Making request for OperationModel\(name=SubmitJob\) "
            r"with params.*?'body': b'(.*?)', "
            r"'url': 'https://batch.*?/v1/submitjob",
            line,
        ):
            if not collect_batch_invocation(match, options, log_group_name, request_id, lines, index, log_group_subrequest_map):
                break

    return log_group_subrequest_map


def get_request_graph(
    options: argparse.Namespace,
    log_group_name: str,
    request_id: str,
    lines: list[str],
    *,
    maxdepth: int = 1,
) -> dict:
    graph: defaultdict = defaultdict(dict)

    log_group_subrequest_map: dict = traverse_logs(options, log_group_name, request_id, lines)

    # query logs for each subrequest group
    for log_subgroup_name, log_group_subrequests in log_group_subrequest_map.items():
        # fetch logs
        if log_group_subrequests[0]["type"] == "lambda":
            subrequest_key = "request_id"
            subrequest_ids = [subrequest[subrequest_key] for subrequest in log_group_subrequests]
            subrequest_logs_map = fetch_request_logs(options, log_subgroup_name, subrequest_ids)
        elif log_group_subrequests[0]["type"] == "batch":
            subrequest_key = "log_stream_name"
            subrequest_ids = [subrequest[subrequest_key] for subrequest in log_group_subrequests]
            subrequest_logs_map = fetch_batch_logs(options, *subrequest_ids)
        else:
            raise RuntimeError(f"internal error: unknown subrequest type {log_group_subrequests}")

        # insert new nodes into graph and traverse deeper
        for subrequest_id in subrequest_ids:
            for subrequest in log_group_subrequests:
                if subrequest[subrequest_key] == subrequest_id:
                    subrequest_info = subrequest
                    break
            else:
                logger.error(
                    "implementation error: subrequest not found "
                    "subrequest_id=%s log_group_subrequests=%r",
                    subrequest_id,
                    log_group_subrequests,
                )
                continue

            subrequest_logs: dict = subrequest_logs_map.get(subrequest_id, {})

            graph[log_subgroup_name][subrequest_id] = {
                **subrequest_info,
                **subrequest_logs,
                "graph": {},
            }

            # maxdepth 0 means unlimited: counting down through the
            # negatives never reaches the 1 that stops traversal
            if maxdepth != 1:
                graph[log_subgroup_name][subrequest_id]["graph"] = get_request_graph(
                    options,
                    log_subgroup_name,
                    subrequest_id,
                    maxdepth=maxdepth - 1,
                    lines=subrequest_logs.get("logs", []),
                )

    return graph


def track_requests(options: argparse.Namespace, *requests: dict) -> dict:
    log_groups: defaultdict = defaultdict(dict)
    for request in requests:
        if request["request_id"] not in log_groups[request["log_group_name"]]:
            log_groups[request["log_group_name"]][request["request_id"]] = request

    graph: defaultdict = defaultdict(dict)
    for log_group_name, request_list in log_groups.items():
        if log_group_name == "/aws/batch/job":
            request_logs = fetch_batch_logs(options, *list(request_list.keys()), timeout=240)
        else:
            request_logs = fetch_request_logs(options, log_group_name, list(request_list.keys()), timeout=240)

        for request_id in request_list:
            graph[log_group_name][request_id] = {
                **request_logs.get(request_id, {"logs": []}),
                **request_list[request_id],
                "graph": get_request_graph(
                    options,
                    log_group_name,
                    request_id,
                    lines=request_logs.get(request_id, {}).get("logs", []),
                    maxdepth=options.maxdepth,
                ),
            }

    return graph


def format_request_line(options: argparse.Namespace, request_id: str, log_group_name: str, request_info: dict) -> str:
    errors: int = 0
    for line in request_info.get("logs", []):
        if "[ERROR]" in line:
            errors += 1

    subrequests_count: int = len(request_info["graph"])

    return options.format.format(
        request_id=request_id,
        log_group_name=log_group_name,
        duration=Decimal(request_info.get("duration") or 0).quantize(Decimal("0.01")),
        memused=request_info.get("memused"),
        memsize=request_info.get("memsize"),
        logcount=len(request_info.get("logs", [])),
        errors=errors,
        subrequests=subrequests_count,
    )


def visualize_graph(options: argparse.Namespace, graph: dict, *, level: int = 0) -> None:
    try:
        maxwidth, _ = os.get_terminal_size()
    except OSError:
        maxwidth = 160

    indent: str = " " * level * 2
    for log_group_name, requests in graph.items():
        for request_id, request_info in requests.items():
            exceptions: list[str] = []
            for line in request_info.get("logs", []):
                if "Exception:" in line:
                    if match := re.search(r"Exception: (.*?)$", line):
                        exceptions.append(match.group(1).strip())

            # the timeline lines are the tool's data product; progress and errors go through the logger
            print(indent + format_request_line(options, request_id, log_group_name, request_info))

            # print exceptions
            if exceptions:
                for exception in exceptions[:3]:
                    shown: str = exception
                    if len(exception) + len(indent) > maxwidth - 12:
                        shown = exception[:maxwidth - len(indent) - 12] + "..."
                    print(indent + "  error: " + shown)
                print(indent + f"  ({len(exceptions)} exceptions)")

            visualize_graph(options, request_info["graph"], level=level + 1)


def save_graph(options: argparse.Namespace, fp: Any, graph: dict, *, level: int = 0) -> None:
    indent: str = " " * level * 2
    for log_group_name, requests in graph.items():
        for request_id, request_info in requests.items():
            fp.write(indent + format_request_line(options, request_id, log_group_name, request_info) + "\n")

            if "invoked_by_log_group_name" in request_info:
                fp.write(indent + "INVOKED BY: {} {}\n".format(
                    request_info["invoked_by_log_group_name"],
                    request_info["invoked_by_request_id"],
                ))

            if payload := request_info.get("payload"):
                fp.write(indent + "PAYLOAD: " + payload + "\n")

            for line in request_info["logs"]:
                fp.write(indent + line + "\n")

            fp.write("\n")

            save_graph(options, fp, request_info["graph"], level=level + 1)


def save_graph_split_per_log_group(options: argparse.Namespace, graph: dict, directory: Path) -> None:
    for log_group_name, requests in graph.items():
        with directory.joinpath(log_group_name.replace("/", "-")).with_suffix(".log").open("a+") as fp:
            for request_id, request_info in requests.items():
                fp.write(format_request_line(options, request_id, log_group_name, request_info) + "\n")

                if "invoked_by_log_group_name" in request_info:
                    fp.write("INVOKED BY: {} {}\n".format(
                        request_info["invoked_by_log_group_name"],
                        request_info["invoked_by_request_id"],
                    ))

                if payload := request_info.get("payload"):
                    fp.write("PAYLOAD: " + payload + "\n")

                for line in request_info["logs"]:
                    fp.write(line + "\n")

                fp.write("\n")

    for log_group_name, requests in graph.items():
        for request_info in requests.values():
            save_graph_split_per_log_group(options, request_info["graph"], directory)


def process(options: argparse.Namespace) -> None:
    if sys.stdin.isatty():
        if not options.log_group_name or not options.request_id:
            logger.error("positional arguments log_group_name and request_id are missing")
            return

        graph = track_requests(options, {"log_group_name": options.log_group_name, "request_id": options.request_id})
    else:
        requests: list[dict] = json.loads(sys.stdin.read())
        graph = track_requests(options, *requests)

    visualize_graph(options, graph)

    if options.output:
        if options.output.lower().endswith(".gz"):
            with gzip.open(options.output, "wt") as gfp:
                save_graph(options, gfp, graph)

        elif options.output.startswith("log-group:"):
            directory: Path = Path(options.output[10:])
            directory.mkdir(parents=True, exist_ok=True)
            save_graph_split_per_log_group(options, graph, directory)

        else:
            with open(options.output, "w") as fp:
                save_graph(options, fp, graph)
                fp.truncate()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "log_group_name",
        nargs="?",
        type=str,
    )
    parser.add_argument(
        "request_id",
        nargs="?",
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
        default="{log_group_name} {request_id} ({duration}s, "
        "{memused}/{memsize} MB, {logcount} lines, "
        "{errors} errors, {subrequests} subrequests)",
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
        help=(
            "Number of days to look back for logs, or time range in "
            "`start_time|end_time` format."
        ),
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
    return parser


def main(argv: list[str] | None = None) -> int:
    options = build_parser().parse_args(argv)
    process(options)
    return 0


if __name__ == "__main__":
    sys.exit(main())
