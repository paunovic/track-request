### Usage

---

```bash
$ track-request --help

usage: track-request [-h] [-v] [-f FORMAT] [-o OUTPUT] [-d DAYS] [-l LIMIT] [-m MAXDEPTH] [log_group_name] [request_id]

positional arguments:
  log_group_name
  request_id

optional arguments:
  -h, --help            show this help message and exit
  -v, --verbose         Verbose mode.
  -f FORMAT, --format FORMAT
                        Output format.
  -o OUTPUT, --output OUTPUT
                        Output file.
  -d DAYS, --days DAYS  Number of days to look back for logs, or time range in `start_time|end_time` format.
  -l LIMIT, --limit LIMIT
                        Maximum number of log lines to fetch per request.
  -m MAXDEPTH, --maxdepth MAXDEPTH
                        Maximum log traversal depth. 0 for unlimited.
```


### Examples

---

TBD
