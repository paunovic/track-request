### Usage

---

```bash
$ python track-request.py --help

usage: python track-request.py [-h] [-v] [-f FORMAT] [-o OUTPUT] [-d DAYS] [-l LIMIT] [-m MAXDEPTH] log_group_name request_id

Trace and analyze AWS Lambda and Batch logs.

positional arguments:
  log_group_name        Initial log group name (e.g., /aws/lambda/my-function or /aws/batch/job).
  request_id            Initial Lambda request ID or AWS Batch log stream name to trace.

optional arguments:
  -h, --help            show this help message and exit
  -v, --verbose         Enable verbose output for debugging.
  -f FORMAT, --format FORMAT
                        Format string for console output summary line. Available keys: request_id, log_group_name, duration, memused, memsize, logcount, errors, subrequests.
  -o OUTPUT, --output OUTPUT
                        Output file path. If ends with .gz, it's gzipped. If starts with 'log-group:', saves split files to the specified directory (e.g., 'log-group:./output_logs/').
  -d DAYS, --days DAYS  Number of days to look back for logs (e.g., '7'), or an absolute time range in 'YYYY-MM-DDTHH:MM:SSZ|YYYY-MM-DDTHH:MM:SSZ' format (e.g., '2023-01-01T00:00:00Z|2023-01-02T00:00:00Z').
  -l LIMIT, --limit LIMIT
                        Maximum number of log lines to fetch per individual CloudWatch query component (e.g., for one Lambda's logs). 0 means default behavior (paginate up to 10,000 or a bit more if many sub-queries).
  -m MAXDEPTH, --maxdepth MAXDEPTH
                        Maximum log traversal depth for sub-requests. 0 for unlimited depth.

Examples
Trace a Lambda request ID, looking back 7 days (default):

python track-request.py /aws/lambda/my-cool-function abcdef12-3456-7890-abcd-ef1234567890

Trace a Batch job log stream, verbose output, looking back 3 days:

python track-request.py /aws/batch/job my-batch-job/default/a1b2c3d4-e5f6-7890-1234-abcdef123456 -v -d 3

Trace a Lambda request ID with a specific time range and save detailed output to a gzipped file:

python track-request.py /aws/lambda/another-function fedcba09-8765-4321-fedc-ba0987654321 -d "2023-10-20T00:00:00Z|2023-10-21T00:00:00Z" -o detailed_trace.log.gz

Trace a request, limit log lines fetched per component to 500, and set max traversal depth to 5:

python track-request.py /aws/lambda/processing-lambda 12345678-abcd-1234-abcd-123456abcdef -l 500 -m 5

Trace a request and save logs split by log group into a directory named trace_outputs:

python track-request.py /aws/lambda/user-service deadbeef-cafe-babe-feed-face12345678 -o "log-group:./trace_outputs/"

Trace a request using a custom output format for the console:

python track-request.py /aws/lambda/my-api-gw-lambda beefcafe-1234-5678-90ab-cdef12345678 -f "{request_id} | Duration: {duration}s | Errors: {errors}"
