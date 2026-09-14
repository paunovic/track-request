"""
Offline aws seams for the tests: a stubber-backed client handed out
through the get_botocore_client boundary.

"""

import os
from collections.abc import Callable, Generator
from contextlib import ExitStack

import pytest
from botocore.client import BaseClient
from botocore.stub import Stubber

import track_request

# dummy credentials and a pinned region so stubber-backed clients
# construct without touching the ambient aws setup or the network
os.environ["AWS_ACCESS_KEY_ID"] = "TESTING"
os.environ["AWS_SECRET_ACCESS_KEY"] = "TESTING"
os.environ["AWS_DEFAULT_REGION"] = "us-east-1"


@pytest.fixture
def stubbed_aws(
    monkeypatch: pytest.MonkeyPatch,
) -> Generator[Callable[[str], tuple[BaseClient, Stubber]], None, None]:
    # a real client wrapped in a botocore Stubber, injected through the
    # get_botocore_client seam; teardown asserts every queued response
    # was consumed
    original_get_botocore_client = track_request.get_botocore_client
    stubbed: dict[str, tuple[BaseClient, Stubber]] = {}

    with ExitStack() as stack:

        def stubbed_pair(service_name: str) -> tuple[BaseClient, Stubber]:
            if service_name not in stubbed:
                client = original_get_botocore_client(service_name)
                stubber = Stubber(client)
                stubber.activate()
                # the stack unwinds in reverse: deactivate stops the
                # interception, then the assert proves every queued
                # response was consumed
                stack.callback(stubber.assert_no_pending_responses)
                stack.callback(stubber.deactivate)
                stubbed[service_name] = (client, stubber)
            return stubbed[service_name]

        monkeypatch.setattr(
            track_request,
            "get_botocore_client",
            lambda service_name: stubbed_pair(service_name)[0],
        )

        yield stubbed_pair
