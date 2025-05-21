#!/usr/bin/env python

import argparse
import gzip
import os
import re
import time
from collections import defaultdict
from decimal import Decimal
from pathlib import Path
from typing import List, Optional, Dict, Tuple, Set, Any, Union

import arrow
import botocore.session
from botocore.client import BaseClient as BotocoreClient

AWS_MAX_RESULTS_PER_QUERY = 10000
DEFAULT_QUERY_LIMIT = 10000

CW_QUERY_POLL_INTERVAL_SECONDS = 2
CW_QUERY_MAX_POLLS = 30
BATCH_DESCRIBE_POLL_INTERVAL_SECONDS = 2
BATCH_DESCRIBE_MAX_POLLS = 120

TIMESTAMP_REGEX = re.compile(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z)")

LAMBDA_INVOKE_REQUEST_REGEX = re.compile(
    r"Making request for OperationModel\(name=Invoke\) with params.*?"
    r"'body': b'(.*?)',.*?"
    r"'url': 'https://lambda.*?/functions/(\w+)/invocations"
)
LAMBDA_INVOKE_RESPONSE_REGEX_TEMPLATE = (
    r"lambda.*?amazonaws\.com.*?POST.*?/functions/{lambda_name}/invocations"
)
LAMBDA_REQUEST_ID_REGEX = re.compile(r"Response headers: .*RequestId': '([a-zA-Z\d-]+)'")

BATCH_SUBMIT_JOB_REQUEST_REGEX = re.compile(
    r"Making request for OperationModel\(name=SubmitJob\) with params.*?"
    r"'body': b'(.*?)',.*?"
    r"'url': 'https://batch.*?/v1/submitjob"
)
BATCH_JOB_ID_REGEX = re.compile(r'"jobId":"([a-zA-Z\d-]+)"')
BATCH_JOB_NAME_REGEX = re.compile(r'"jobName":"(\w+)"')
BATCH_JOB_NAME_BASE_REGEX = re.compile(r"^(.*)_\d+$")

args: Optional[argparse.Namespace] = None

def get_botocore_client(service: str, region_name: Optional[str] = None) -> BotocoreClient:
    client_config: Dict[str, Any] = {
        "aws_access_key_id": os.environ.get("AWS_ACCESS_KEY_ID"),
        "aws_secret_access_key": os.environ.get("AWS_SECRET_ACCESS_KEY"),
        "aws_session_token": os.environ.get("AWS_SESSION_TOKEN"),
    }
    if region_name:
        client_config["region_name"] = region_name

    client_config = {k: v for k, v in client_config.items() if v is not None}

    session = botocore.session.get_session()
    return session.create_client(service_name=service, **client_config)

def parse_timestamp_from_line(line: str) -> Optional[arrow.Arrow]:
    if match := TIMESTAMP_REGEX.search(line):
        return arrow.get(match.group(1))
    return None

def parse_cloudwatch_result_fields(result_item: List[Dict[str, str]], *keys: str) -> Tuple[Optional[str], ...]:
    extracted_values: Dict[str, Optional[str]] = {key: None for key in keys}
    for field_dict in result_item:
        field_name = field_dict.get("field")
        if field_name in extracted_values:
            extracted_values[field_name] = field_dict.get("value")

    return tuple(extracted_values[key] for key in keys)

def _poll_cloudwatch_query(cloudwatch_client: BotocoreClient, query_id: str) -> Optional[Dict[str, Any]]:
    for _ in range(CW_QUERY_MAX_POLLS):
        try:
            response = cloudwatch_client.get_query_results(queryId=query_id)
            if response and response.get("status") == "Complete":
                return response
            if response and response.get("status") in ["Failed", "Cancelled", "Timeout"]:
                if args and args.verbose:
                    print(f"Warning: Query {query_id} ended with status: {response.get('status')}")
                return response
        except Exception as e:
            if args and args.verbose:
                print(f"Error polling query {query_id}: {e}")
            return None
        time.sleep(CW_QUERY_POLL_INTERVAL_SECONDS)
    if args and args.verbose:
        print(f"Warning: Query {query_id} timed out after {CW_QUERY_MAX_POLLS * CW_QUERY_POLL_INTERVAL_SECONDS}s.")
    return None

def execute_cloudwatch_query(log_group_name: str, query_string: str) -> Optional[Dict[str, Any]]:
    if not args:
        raise ValueError("Global 'args' not initialized. Call parse_args() first.")
        
    if args.verbose:
        print(f"Fetching logs for {log_group_name}: {query_string}")

    try:
        days_offset = int(args.days)
        start_time_arrow = arrow.utcnow().shift(days=-days_offset)
        end_time_arrow = arrow.utcnow()
    except ValueError:
        time_parts = args.days.split("|")
        if len(time_parts) != 2:
            raise ValueError("Invalid time range format for --days. Expected 'N' or 'start_time|end_time'.")
        start_time_arrow = arrow.get(time_parts[0].strip())
        end_time_arrow = arrow.get(time_parts[1].strip())

    cloudwatch_client = get_botocore_client("logs")
    
    query_limit = min(args.limit or DEFAULT_QUERY_LIMIT, AWS_MAX_RESULTS_PER_QUERY)

    try:
        start_query_response = cloudwatch_client.start_query(
            logGroupName=log_group_name,
            queryString=query_string,
            startTime=int(start_time_arrow.timestamp() * 1000),
            endTime=int(end_time_arrow.timestamp() * 1000),
            limit=query_limit,
        )
    except Exception as e:
        print(f"Error starting CloudWatch query for {log_group_name}: {e}")
        return None
        
    query_id: str = start_query_response.get("queryId")
    if not query_id:
        print(f"Error: start_query did not return a queryId. Response: {start_query_response}")
        return None

    final_response = _poll_cloudwatch_query(cloudwatch_client, query_id)

    if not final_response or final_response.get("status") != "Complete":
        print(f"Query {query_id} for {log_group_name} did not complete successfully. Status: {final_response.get('status') if final_response else 'Unknown'}")
        return final_response

    for iteration in range(1, CW_QUERY_MAX_POLLS):
        current_results_count = len(final_response.get("results", []))
        
        if current_results_count < AWS_MAX_RESULTS_PER_QUERY:
            break
        if args.limit and current_results_count >= args.limit:
            break
        
        last_result_item = final_response["results"][-1]
        timestamp_str_tuple = parse_cloudwatch_result_fields(last_result_item, "@timestamp")
        if not timestamp_str_tuple or not timestamp_str_tuple[0]:
            if args.verbose:
                print(f"Warning: Could not parse @timestamp from last result for pagination: {last_result_item}")
            break 
        last_timestamp_arrow = arrow.get(timestamp_str_tuple[0])

        remaining_limit = (args.limit - current_results_count) if args.limit else AWS_MAX_RESULTS_PER_QUERY
        sub_query_limit = min(remaining_limit, AWS_MAX_RESULTS_PER_QUERY)

        if sub_query_limit <= 0:
            break

        if args.verbose:
            print(f"Fetching next chunk for {log_group_name} (iteration {iteration}): {query_string}")

        try:
            sub_start_query_response = cloudwatch_client.start_query(
                logGroupName=log_group_name,
                queryString=query_string,
                startTime=int(last_timestamp_arrow.timestamp() * 1000),
                endTime=int(end_time_arrow.timestamp() * 1000),
                limit=sub_query_limit,
            )
        except Exception as e:
            print(f"Error starting subsequent CloudWatch query for {log_group_name}: {e}")
            break

        sub_query_id: str = sub_start_query_response.get("queryId")
        if not sub_query_id:
            print(f"Error: subsequent start_query did not return a queryId. Response: {sub_start_query_response}")
            break

        sub_response = _poll_cloudwatch_query(cloudwatch_client, sub_query_id)

        if not sub_response or sub_response.get("status") != "Complete" or "results" not in sub_response or not sub_response["results"]:
            if args.verbose:
                status = sub_response.get("status") if sub_response else "No response"
                print(f"Sub-query {sub_query_id} for {log_group_name} did not yield results. Status: {status}")
            break

        first_new_result_item = sub_response["results"][0]
        new_ts_str, new_msg_str = parse_cloudwatch_result_fields(first_new_result_item, "@timestamp", "@message")

        if new_ts_str is None:
             if args.verbose:
                print(f"Warning: Could not parse @timestamp from first new result for de-duplication: {first_new_result_item}")
             final_response["results"].extend(sub_response["results"])
             continue

        slice_index = len(final_response["results"])
        for i in range(len(final_response["results"]) - 1, -1, -1):
            current_ts_str, current_msg_str = parse_cloudwatch_result_fields(final_response["results"][i], "@timestamp", "@message")
            if current_ts_str == new_ts_str and current_msg_str == new_msg_str:
                slice_index = i 
            elif arrow.get(current_ts_str) < arrow.get(new_ts_str):
                break 
        
        final_response["results"] = final_response["results"][:slice_index]
        final_response["results"].extend(sub_response["results"])
        
    if args and args.limit and final_response and len(final_response.get("results", [])) > args.limit:
         final_response["results"] = final_response["results"][:args.limit]
         if args.verbose:
            print(f"Results truncated to user-defined limit: {args.limit}")

    return final_response

def _fetch_logs_in_batches(
    log_group_name: str,
    ids: List[str],
    id_field_name: str,
    query_template: str,
    timeout_per_batch: int = 60,
    batch_size: int = 10
) -> Dict[str, Dict[str, Any]]:
    if not args:
        raise ValueError("Global 'args' not initialized.")

    logs_map: Dict[str, Dict[str, Any]] = {}
    
    for i in range(0, len(ids), batch_size):
        current_batch_ids = ids[i:i + batch_size]
        ids_to_find_in_batch = set(current_batch_ids)
        processed_ids_in_batch: Set[str] = set()
        
        start_time = time.perf_counter()
        current_timeout = timeout_per_batch

        while ids_to_find_in_batch - processed_ids_in_batch and (time.perf_counter() - start_time) < current_timeout:
            ids_for_this_query_attempt = list(ids_to_find_in_batch - processed_ids_in_batch)
            if not ids_for_this_query_attempt: break

            query = query_template.format(id_field_name, ",".join(f"'{r}'" for r in ids_for_this_query_attempt))
            response = execute_cloudwatch_query(log_group_name, query)

            if response and response.get("results"):
                found_in_this_response: Set[str] = set()
                for result_item in response["results"]:
                    parsed_id_tuple = parse_cloudwatch_result_fields(result_item, id_field_name)
                    item_id = parsed_id_tuple[0] if parsed_id_tuple else None

                    if item_id and item_id in ids_to_find_in_batch:
                        found_in_this_response.add(item_id)
                        pass
                
                processed_ids_in_batch.update(found_in_this_response)

            if processed_ids_in_batch == ids_to_find_in_batch:
                break 
            
            time.sleep(3)
        
        pass

    return logs_map

def fetch_request_logs(log_group_name: str, request_ids: List[str], *, timeout_per_batch: int = 60) -> Dict[str, Dict[str, Any]]:
    if not args:
        raise ValueError("Global 'args' not initialized.")

    request_logs_map: Dict[str, Dict[str, Any]] = defaultdict(lambda: {"logs": []})
    batch_size = 10

    for i in range(0, len(request_ids), batch_size):
        current_batch_ids = request_ids[i:i + batch_size]
        
        ids_filter_string = ",".join(f"'{r_id}'" for r_id in current_batch_ids)
        query = (
            f"fields @requestId, @timestamp, @message"
            f" | filter @requestId in [{ids_filter_string}]"
            f" | sort @timestamp asc"
        )
        
        response = execute_cloudwatch_query(log_group_name, query)

        if not response or not response.get("results"):
            if args.verbose:
                print(f"Warning: No results or invalid response for batch query in {log_group_name} for IDs: {current_batch_ids}. Response: {response}")
            continue

        for result_item in response["results"]:
            req_id, message = parse_cloudwatch_result_fields(result_item, "@requestId", "@message")
            
            if req_id and message:
                message = message.replace(f"\t{req_id}\t", "  ").strip(" \n")
                request_logs_map[req_id]["logs"].append(message)

                report_regex = (
                    fr"REPORT RequestId: {re.escape(req_id)}\s+Duration: ([\d.]+)\s*ms\s+Billed Duration: ([\d.]+)\s*ms"
                    fr"\s+Memory Size: (\d+)\s*MB\s+Max Memory Used: (\d+)\s*MB"
                )
                if match := re.search(report_regex, message, re.IGNORECASE):
                    try:
                        request_logs_map[req_id]["duration"] = float(match.group(2)) / 1000.0
                        request_logs_map[req_id]["memsize"] = int(match.group(3))
                        request_logs_map[req_id]["memused"] = int(match.group(4))
                    except (ValueError, IndexError) as e:
                        if args.verbose:
                            print(f"Warning: Could not parse REPORT line fields for {req_id}: {message}. Error: {e}")
            elif args.verbose:
                print(f"Warning: Unable to parse @requestId or @message from result item: {result_item}")
                
    return dict(request_logs_map)

def fetch_batch_job_logs(*log_stream_names: str, timeout_per_batch: int = 60) -> Dict[str, Dict[str, Any]]:
    if not args:
        raise ValueError("Global 'args' not initialized.")

    log_stream_logs_map: Dict[str, Dict[str, Any]] = defaultdict(lambda: {"logs": [], "start_time": None, "end_time": None})
    batch_size = 10
    log_group_name = "/aws/batch/job"

    log_stream_list = list(log_stream_names)

    for i in range(0, len(log_stream_list), batch_size):
        current_batch_streams = log_stream_list[i:i + batch_size]
        
        ids_filter_string = ",".join(f"'{stream_name}'" for stream_name in current_batch_streams)
        query = (
            f"fields @logStream, @timestamp, @message"
            f" | filter @logStream in [{ids_filter_string}]"
            f" | sort @timestamp asc"
        )

        response = execute_cloudwatch_query(log_group_name, query)

        if not response or not response.get("results"):
            if args.verbose:
                print(f"Warning: No results for batch job log query for streams: {current_batch_streams}. Response: {response}")
            continue

        for result_item in response["results"]:
            stream_name, message, timestamp_str = parse_cloudwatch_result_fields(result_item, "@logStream", "@message", "@timestamp")

            if stream_name and message and timestamp_str:
                message = message.strip(" \n")
                log_stream_logs_map[stream_name]["logs"].append(message)
                
                current_ts_arrow = arrow.get(timestamp_str)
                if not log_stream_logs_map[stream_name]["start_time"] or current_ts_arrow < arrow.get(log_stream_logs_map[stream_name]["start_time"]):
                    log_stream_logs_map[stream_name]["start_time"] = timestamp_str
                if not log_stream_logs_map[stream_name]["end_time"] or current_ts_arrow > arrow.get(log_stream_logs_map[stream_name]["end_time"]):
                    log_stream_logs_map[stream_name]["end_time"] = timestamp_str
            elif args.verbose:
                print(f"Warning: Unable to parse fields from Batch log result item: {result_item}")

    for stream_name, log_data in log_stream_logs_map.items():
        if log_data["start_time"] and log_data["end_time"]:
            try:
                duration_seconds = (arrow.get(log_data["end_time"]) - arrow.get(log_data["start_time"])).total_seconds()
                log_data["duration"] = duration_seconds
            except Exception as e:
                if args.verbose:
                    print(f"Warning: Could not calculate duration for Batch log stream {stream_name}. Error: {e}")
                log_data["duration"] = None
        else:
            log_data["duration"] = None

    return dict(log_stream_logs_map)

def traverse_and_identify_sub_requests(
    invoking_log_group_name: str,
    invoking_request_id: str,
    log_lines: List[str]
) -> Dict[str, List[Dict[str, Any]]]:
    if not args:
        raise ValueError("Global 'args' not initialized.")

    sub_requests_map: Dict[str, List[Dict[str, Any]]] = defaultdict(list)

    for line_index, line_content in enumerate(log_lines):
        lambda_match = LAMBDA_INVOKE_REQUEST_REGEX.search(line_content)
        if lambda_match:
            payload_str: str = lambda_match.group(1)
            target_lambda_name: str = lambda_match.group(2)
            target_log_group_name = f"/aws/lambda/{target_lambda_name}"
            
            found_lambda_req_id = False
            for sub_line_idx in range(line_index + 1, min(line_index + 1 + 100, len(log_lines))):
                sub_line = log_lines[sub_line_idx]
                if re.search(LAMBDA_INVOKE_RESPONSE_REGEX_TEMPLATE.format(lambda_name=target_lambda_name), sub_line):
                    if req_id_match := LAMBDA_REQUEST_ID_REGEX.search(sub_line):
                        sub_request_id = req_id_match.group(1)
                        sub_requests_map[target_log_group_name].append({
                            "type": "lambda",
                            "log_group_name": target_log_group_name,
                            "request_id": sub_request_id,
                            "invoked_by_log_group_name": invoking_log_group_name,
                            "invoked_by_request_id": invoking_request_id,
                            "payload": payload_str,
                        })
                        found_lambda_req_id = True
                        break
            if not found_lambda_req_id and args.verbose:
                print(f"Warning: Could not find Lambda RequestId for invocation of {target_lambda_name} near: {line_content[:200]}")
            continue

        batch_match = BATCH_SUBMIT_JOB_REQUEST_REGEX.search(line_content)
        if batch_match:
            body_str: str = batch_match.group(1)
            target_batch_log_group = "/aws/batch/job"
            
            found_batch_details = False
            for sub_line_idx in range(line_index + 1, min(line_index + 1 + 100, len(log_lines))):
                sub_line = log_lines[sub_line_idx]
                if job_id_match := BATCH_JOB_ID_REGEX.search(sub_line):
                    job_id = job_id_match.group(1)
                    batch_client = get_botocore_client("batch")
                    
                    log_stream_name: Optional[str] = None
                    job_details_response: Optional[Dict[str, Any]] = None
                    for _ in range(BATCH_DESCRIBE_MAX_POLLS):
                        try:
                            job_details_response = batch_client.describe_jobs(jobs=[job_id])
                            if job_details_response and job_details_response.get("jobs"):
                                job_info = job_details_response["jobs"][0]
                                if job_info.get("container", {}).get("logStreamName") and \
                                   job_info.get("status") in ("SUCCEEDED", "FAILED"):
                                    log_stream_name = job_info["container"]["logStreamName"]
                                    break
                                if job_info.get("status") in ("SUCCEEDED", "FAILED", "RUNNABLE"):
                                    if job_info.get("container", {}).get("logStreamName"):
                                        log_stream_name = job_info["container"]["logStreamName"]
                            else:
                                break 
                        except Exception as e:
                            if args.verbose:
                                print(f"Error describing batch job {job_id}: {e}")
                            break
                        time.sleep(BATCH_DESCRIBE_POLL_INTERVAL_SECONDS)
                    
                    mem_size = job_details_response["jobs"][0]["container"]["memory"] if job_details_response and job_details_response.get("jobs") else "?"

                    if log_stream_name:
                        sub_requests_map[target_batch_log_group].append({
                            "type": "batch",
                            "job_id": job_id,
                            "log_stream_name": log_stream_name,
                            "memused": "?",
                            "memsize": mem_size,
                            "invoked_by_log_group_name": invoking_log_group_name,
                            "invoked_by_request_id": invoking_request_id,
                            "payload": body_str,
                        })
                        found_batch_details = True
                    else:
                        if args.verbose:
                            print(f"Warning: Could not get logStreamName for Batch job {job_id} via describe_jobs. Fallback not implemented in this version.")
                        sub_requests_map[target_batch_log_group].append({
                            "type": "batch", "job_id": job_id, "log_stream_name": f"UNKNOWN_LOG_STREAM_FOR_{job_id}",
                            "memused": "?", "memsize": mem_size,
                            "invoked_by_log_group_name": invoking_log_group_name,
                            "invoked_by_request_id": invoking_request_id, "payload": body_str,
                        })
                        found_batch_details = True
                    break
            if not found_batch_details and args.verbose:
                 print(f"Warning: Could not find Batch JobId for submission near: {line_content[:200]}")
    return dict(sub_requests_map)

def build_request_graph_recursively(
    current_log_group: str,
    current_request_id: str,
    current_log_lines: List[str],
    *,
    max_depth: int
) -> Dict[str, Any]:
    if not args:
        raise ValueError("Global 'args' not initialized.")

    if max_depth == 0 and args.maxdepth != 0:
        return {}

    sub_request_groups = traverse_and_identify_sub_requests(
        current_log_group, current_request_id, current_log_lines
    )

    populated_graph: Dict[str, Dict[str, Any]] = defaultdict(dict)

    for target_lg_name, sub_req_infos_list in sub_request_groups.items():
        if not sub_req_infos_list:
            continue

        sub_request_type = sub_req_infos_list[0]["type"]
        
        fetched_sub_logs_map: Dict[str, Dict[str, Any]] = {}
        if sub_request_type == "lambda":
            sub_ids_to_fetch = [info["request_id"] for info in sub_req_infos_list if "request_id" in info]
            if sub_ids_to_fetch:
                fetched_sub_logs_map = fetch_request_logs(target_lg_name, sub_ids_to_fetch)
        elif sub_request_type == "batch":
            sub_ids_to_fetch = [info["log_stream_name"] for info in sub_req_infos_list if "log_stream_name" in info and not info["log_stream_name"].startswith("UNKNOWN_")]
            if sub_ids_to_fetch:
                fetched_sub_logs_map = fetch_batch_job_logs(*sub_ids_to_fetch)
        
        for sub_req_info in sub_req_infos_list:
            key_id: Optional[str] = None
            if sub_request_type == "lambda":
                key_id = sub_req_info.get("request_id")
            elif sub_request_type == "batch":
                key_id = sub_req_info.get("log_stream_name")
            
            if not key_id: continue

            full_sub_req_details = {**sub_req_info, **fetched_sub_logs_map.get(key_id, {"logs": []})}
            
            sub_graph = build_request_graph_recursively(
                target_lg_name,
                key_id,
                full_sub_req_details.get("logs", []),
                max_depth=max_depth -1 if args.maxdepth !=0 else 0
            )
            full_sub_req_details["graph"] = sub_graph
            populated_graph[target_lg_name][key_id] = full_sub_req_details
            
    return dict(populated_graph)

def trace_initial_requests(initial_requests_info: List[Dict[str, str]]) -> Dict[str, Any]:
    if not args:
        raise ValueError("Global 'args' not initialized.")

    grouped_requests: Dict[str, Dict[str, Dict[str,str]]] = defaultdict(dict)
    for req_info in initial_requests_info:
        lg_name = req_info["log_group_name"]
        req_id_or_stream = req_info["request_id"] 
        grouped_requests[lg_name][req_id_or_stream] = req_info

    final_graph: Dict[str, Dict[str, Any]] = defaultdict(dict)

    for lg_name, ids_map in grouped_requests.items():
        ids_list = list(ids_map.keys())
        fetched_logs_for_group: Dict[str, Dict[str, Any]] = {}

        if lg_name == "/aws/batch/job":
            fetched_logs_for_group = fetch_batch_job_logs(*ids_list, timeout_per_batch=240)
        else:
            fetched_logs_for_group = fetch_request_logs(lg_name, ids_list, timeout_per_batch=240)

        for item_id, initial_info_dict in ids_map.items():
            combined_info = {
                **initial_info_dict,
                **fetched_logs_for_group.get(item_id, {"logs": []})
            }
            
            sub_graph = build_request_graph_recursively(
                lg_name,
                item_id,
                combined_info.get("logs", []),
                max_depth=args.maxdepth
            )
            combined_info["graph"] = sub_graph
            final_graph[lg_name][item_id] = combined_info
            
    return dict(final_graph)

def format_request_summary_line(request_id: str, log_group_name: str, request_info: Dict[str, Any], format_str: str) -> str:
    errors = 0
    exceptions_list = []
    for line in request_info.get("logs", []):
        if "[ERROR]" in line:
            errors += 1
        if "[ERROR]" in line and "Exception:" in line:
            if match := re.search(r"Exception: (.*?)$", line):
                exceptions_list.append(match.group(1).strip())
    
    subrequests_count = 0
    if request_info.get("graph"):
        for sub_lg_name, sub_reqs_dict in request_info["graph"].items():
            subrequests_count += len(sub_reqs_dict)

    duration_val = request_info.get("duration")
    memused_val = request_info.get("memused")
    memsize_val = request_info.get("memsize")

    return format_str.format(
        request_id=request_id,
        log_group_name=log_group_name,
        duration=Decimal(duration_val or 0).quantize(Decimal("0.01")) if isinstance(duration_val, (int, float)) else "?.??",
        memused=memused_val if memused_val is not None else "?",
        memsize=memsize_val if memsize_val is not None else "?",
        logcount=len(request_info.get("logs", [])),
        errors=errors,
        subrequests=subrequests_count,
    )

def visualize_graph_to_console(graph_data: Dict[str, Any], current_level: int = 0) -> None:
    if not args:
        raise ValueError("Global 'args' not initialized.")
        
    try:
        terminal_max_width, _ = os.get_terminal_size()
    except OSError:
        terminal_max_width = 160

    indent_space = "  " * current_level
    for lg_name, requests_dict in graph_data.items():
        for req_id, req_info in requests_dict.items():
            summary_line = format_request_summary_line(req_id, lg_name, req_info, args.format)
            print(indent_space + summary_line)

            exceptions_found = []
            for log_line in req_info.get("logs", []):
                 if "[ERROR]" in log_line and "Exception:" in log_line:
                    if match := re.search(r"Exception: (.*?)$", log_line):
                        exceptions_found.append(match.group(1).strip())
            
            if exceptions_found:
                for i, exc_msg in enumerate(exceptions_found[:3]):
                    max_exc_len = terminal_max_width - len(indent_space) - len("  error: ") - 3
                    if len(exc_msg) > max_exc_len:
                        exc_msg = exc_msg[:max_exc_len] + "..."
                    print(indent_space + "  error: " + exc_msg)
                if len(exceptions_found) > 3:
                    print(indent_space + f"  ({len(exceptions_found) - 3} more exceptions)")

            visualize_graph_to_console(req_info.get("graph", {}), current_level + 1)

def save_graph_to_file(output_file_stream: Any, graph_data: Dict[str, Any], current_level: int = 0) -> None:
    if not args:
        raise ValueError("Global 'args' not initialized.")

    indent_space = "  " * current_level
    for lg_name, requests_dict in graph_data.items():
        for req_id, req_info in requests_dict.items():
            summary_line = format_request_summary_line(req_id, lg_name, req_info, args.format)
            output_file_stream.write(indent_space + summary_line + "\n")

            if "invoked_by_log_group_name" in req_info:
                output_file_stream.write(
                    f"{indent_space}  INVOKED BY: {req_info['invoked_by_log_group_name']} {req_info['invoked_by_request_id']}\n"
                )
            if url := req_info.get("url"):
                output_file_stream.write(f"{indent_space}  URL: {url}\n")
            if payload := req_info.get("payload"):
                output_file_stream.write(f"{indent_space}  PAYLOAD: {str(payload)}\n")

            for log_line in req_info.get("logs", []):
                output_file_stream.write(indent_space + "  LOG: " + log_line + "\n")
            
            output_file_stream.write("\n")

            save_graph_to_file(output_file_stream, req_info.get("graph", {}), current_level + 1)

def save_graph_split_by_log_group(graph_data: Dict[str, Any], output_directory: Path) -> None:
    if not args:
        raise ValueError("Global 'args' not initialized.")

    output_directory.mkdir(parents=True, exist_ok=True)

    def _append_to_log_group_file(lg_name_to_save: str, req_id_to_save: str, req_info_to_save: Dict[str, Any]):
        file_path = output_directory.joinpath(lg_name_to_save.replace("/", "-").replace(":", "_") + ".log")
        with file_path.open("a+", encoding="utf-8") as fp:
            summary_line = format_request_summary_line(req_id_to_save, lg_name_to_save, req_info_to_save, args.format)
            fp.write(summary_line + "\n")

            if "invoked_by_log_group_name" in req_info_to_save:
                fp.write(
                    f"  INVOKED BY: {req_info_to_save['invoked_by_log_group_name']} {req_info_to_save['invoked_by_request_id']}\n"
                )
            if url := req_info_to_save.get("url"):
                fp.write(f"  URL: {url}\n")
            if payload := req_info_to_save.get("payload"):
                fp.write(f"  PAYLOAD: {str(payload)}\n")
            
            for log_line in req_info_to_save.get("logs", []):
                fp.write("  LOG: " + log_line + "\n")
            fp.write("\n")

    def _recursive_save_split(current_graph_level: Dict[str, Any]):
        for lg_name, requests_dict in current_graph_level.items():
            for req_id, req_info in requests_dict.items():
                _append_to_log_group_file(lg_name, req_id, req_info)
                if req_info.get("graph"):
                    _recursive_save_split(req_info["graph"])
    
    _recursive_save_split(graph_data)

def main_process() -> None:
    if not args:
        raise ValueError("Global 'args' not initialized. Call parse_args() first.")

    initial_request = {
        "log_group_name": args.log_group_name,
        "request_id": args.request_id,
    }
    
    full_graph = trace_initial_requests([initial_request])

    visualize_graph_to_console(full_graph)

    if args.output:
        output_path_str = args.output
        if output_path_str.lower().endswith(".gz"):
            with gzip.open(output_path_str, "wt", encoding="utf-8") as gfp:
                save_graph_to_file(gfp, full_graph)
            print(f"\nDetailed graph saved to gzipped file: {output_path_str}")
        elif output_path_str.startswith("log-group:"):
            dir_path_str = output_path_str[len("log-group:"):]
            if not dir_path_str:
                print("Error: No directory specified for log-group output. Example: log-group:/path/to/output_dir")
                return
            directory = Path(dir_path_str)
            save_graph_split_by_log_group(full_graph, directory)
            print(f"\nDetailed graph saved (split by log group) to directory: {directory}")
        else:
            with open(output_path_str, "w", encoding="utf-8") as fp:
                save_graph_to_file(fp, full_graph)
            print(f"\nDetailed graph saved to file: {output_path_str}")

def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Trace and analyze AWS Lambda and Batch logs.")
    parser.add_argument(
        "log_group_name",
        type=str,
        help="Initial log group name (e.g., /aws/lambda/my-function or /aws/batch/job).",
    )
    parser.add_argument(
        "request_id",
        type=str,
        help="Initial Lambda request ID or AWS Batch log stream name to trace.",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output for debugging.",
    )
    parser.add_argument(
        "-f", "--format",
        type=str,
        default="{log_group_name} {request_id} ({duration}s, {memused}/{memsize}MB, {logcount} lines, {errors} errors, {subrequests} subrequests)",
        help="Format string for console output summary line. Available keys: request_id, log_group_name, duration, memused, memsize, logcount, errors, subrequests.",
    )
    parser.add_argument(
        "-o", "--output",
        type=str,
        default=None,
        help="Output file path. If ends with .gz, it's gzipped. "
             "If starts with 'log-group:', saves split files to the specified directory (e.g., 'log-group:./output_logs/').",
    )
    parser.add_argument(
        "-d", "--days",
        type=str,
        default="7",
        help="Number of days to look back for logs (e.g., '7'), or an absolute time range "
             "in 'YYYY-MM-DDTHH:MM:SSZ|YYYY-MM-DDTHH:MM:SSZ' format (e.g., '2023-01-01T00:00:00Z|2023-01-02T00:00:00Z').",
    )
    parser.add_argument(
        "-l", "--limit",
        type=int,
        default=0,
        help="Maximum number of log lines to fetch per individual CloudWatch query component (e.g., for one Lambda's logs). "
             "0 means default behavior (paginate up to 10,000 or a bit more if many sub-queries).",
    )
    parser.add_argument(
        "-m", "--maxdepth",
        type=int,
        default=10,
        help="Maximum log traversal depth for sub-requests. 0 for unlimited depth.",
    )
    return parser.parse_args()

if __name__ == "__main__":
    args = parse_arguments()
    try:
        main_process()
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        if args and args.verbose:
            import traceback
            traceback.print_exc()
