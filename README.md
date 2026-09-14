# track-request

follow one request through a serverless stack: which lambdas it
invoked, which batch jobs it submitted, what each printed - the
whole tree, with durations, memory, log counts and errors per node:

    $ track-request /aws/lambda/api-prod 8f6e1b

    /aws/lambda/api-prod 8f6e1b (1.24s, 134/512 MB, 210 lines, 0 errors, 2 subrequests)
      /aws/lambda/process-order 2a9c7d (0.98s, 201/512 MB, 118 lines, 0 errors, 1 subrequests)
        /aws/batch/job/default/7f3e5a (12.40s, ?/2048 MB, 55 lines, 0 errors, 0 subrequests)
      /aws/lambda/send-email 91dd02 (0.31s, 84/512 MB, 12 lines, 0 errors, 0 subrequests)

queries cloudwatch insights for the request's logs, reads the aws sdk debug lines
to find every lambda invocation and batch submission in them, fetches those requests too,
and recurses.

## usage

    usage: track-request [-h] [-v] [-f FORMAT] [-o OUTPUT] [-d DAYS]
                         [-l LIMIT] [-m MAXDEPTH]
                         log_group_name request_id

- `-f FORMAT` - row template; the default shows group, id, duration, memory, lines, errors and subrequest count
- `-o OUTPUT` - also write the full logs to a file; a name ending in `.gz` compresses, the prefix `log-group:` splits output into one file per log group
- `-d DAYS` - how far back to search: a number of days, or `start|end` timestamps
- `-l LIMIT` - stop after this many log lines per request
- `-m MAXDEPTH` - traversal depth, 0 for unlimited

## install

a python package with a single dependency, botocore, on python 3.10 or newer:

    uv tool install git+https://github.com/paunovic/track-request.git

or plain pip:

    pip install git+https://github.com/paunovic/track-request.git

credentials come from the ambient aws chain - environment variables, profiles, etc.
