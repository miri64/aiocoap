# SPDX-FileCopyrightText: Christian Amsüss and the aiocoap contributors
#
# SPDX-License-Identifier: MIT

"""Tests that use pytest-pyodide to run tests in an actual browser, allowing
testing of the websocket shim.

Unlike all other tests, this only runs in pytest and not in unittest.
Conveniently, unittest does not recurse unless there is an `__init__.py`, so we
don't put one in, pytest still finds it, and some crative .

This has some unusual dependencies that are not installed with the regular
tests, and it does not make sense to run this with different host Python
versions. Instead, it is set up independently in the CI config.

Running this needs an actual browser and not just node; thus, pytest needs to
be invoked with ``--runtime firefox``.
"""

import asyncio
import unittest

import pytest

try:
    from pytest_pyodide.decorator import run_in_pyodide_coverage, copy_files_to_pyodide
except ImportError:
    pytest.skip(allow_module_level=True, reason="pytest_pyodide not available")

# We'd add an __init__.py and do `from ..test_server import`, but then unittest
# would try to ingest this module, and that has no allow_module_level
# functionaltiy to exit late -- and other workarounds such as putting
# everything into the else clause of the import have caused test failures
# elsewhere (likely due to assumptions by the decorators).
import sys
from pathlib import Path

sys.path.append(Path(__file__).parent.parent.parent)
from tests.test_server import WithTestServer

# so let's see what does work easily:

# this is not enough: we need a test server too:

# @copy_files_to_pyodide(file_list=[("dist", "dist")])
# @run_in_pyodide_coverage()
# async def test_pyodidebasic(selenium):
#     import aiocoap
#
#     ctx = await aiocoap.Context.create_client_context()
#     await ctx.request(
#         aiocoap.Message(code=aiocoap.GET, uri="coaps+ws://demo.coap.amsuess.com/whoami")
#     ).response

# … and doing it manually (when we'd have all the control we want to set up the
# server) won't give us the neat copy_files_to_pyodide and _coverage:

# def test_manual_basics(selenium):
#     # we could do some setup here
#     selenium.run("import asyncio")

# pytest should generally work well with unittest -- but this is not working,
# probably because pytest plays well with unittest.TestCase but not with
# unittest.IsolatedAsyncioTestCase

# @pytest.mark.usefixtures("selenium")
# class TestPyodide(WithTestServer):
#     def test_basic(self):
#         selenium.run("True")

# so let's build our own pytest fixture out of parts of WithTestServer.
#
# but we can'd do it like this b/c the selenium server probably blocks main:

# @pytest_asyncio.fixture(scope="session")
# async def local_ws_server():
#     unittest_backing = WithTestServer()
#     await unittest_backing.asyncSetUp()
#     class DummySuccess:
#         # so that we don't need to go through another class to mock ._outcome.result._excinfo
#         result = property(lambda self: self)
#
#         _excinfo = None
#     unittest_backing._outcome = DummySuccess()
#
#     yield "Don't use this value, but rely on coap+ws running on port 8683 instead"
#
#     await unittest_backing.asyncTearDown()

# so in the end, there's a lot to do manually:


class my_run_in_pyodide_coverage(run_in_pyodide_coverage):
    """Customizing coverage details because our pyproject.toml has non-default
    settings (different path, parallel mode)."""

    TOTAL = 1

    def _process_extra(self, coverage_out_binary):
        from pathlib import Path
        import socket
        import os
        from base64 import b64decode

        count = type(self).TOTAL
        type(self).TOTAL += 1
        # not doing hex because how likely is it really?
        coverage_path = Path(
            f".coverage/cov.emscripten-{socket.gethostname()}.pid{os.getpid()}.{count}"
        )

        coverage_path.write_bytes(b64decode(coverage_out_binary))


@copy_files_to_pyodide(file_list=[("dist/*.whl", "dist/")])  # for the .whl installation
@my_run_in_pyodide_coverage(coverage_args=dict(source_pkgs=["aiocoap"]))
async def test_pyodidebasic(selenium, local_ws_server):
    import aiocoap

    ctx = await aiocoap.Context.create_client_context()
    response = await ctx.request(
        aiocoap.Message(code=aiocoap.GET, uri="coap+ws://localhost:8683/whoami")
    ).response_raising

    assert "coap+ws" in response.payload.decode("utf8")


# scoping to session because there should be no way by which the client can
# modify the server's state
@pytest.fixture(scope="session")
def local_ws_server():
    """A fixture that makes a coap+ws test server available under the
    adversarial condition that it's called on a synchronous main thread but
    that thread will be blocked while we actually need data from the server, so
    we

    * spawn a thread
    * run async'ly in that thread
    * do thread-safe IPC to signal readiness and when to shut down the fixture
      again
    """
    import threading
    import concurrent.futures

    is_ready = concurrent.futures.Future()

    t = threading.Thread(target=local_ws_server_thread, kwargs=dict(is_ready=is_ready))
    t.start()

    shut_down = is_ready.result()
    yield "Server for coap+ws running on port 8683, connect to that."

    shut_down()

    t.join()


def local_ws_server_thread(is_ready):
    try:
        asyncio.run(local_ws_server_async(is_ready))
    except Exception as e:
        is_ready.set_exception(e)
    else:
        if not is_ready.done():
            is_ready.set_exception(
                RuntimeError(
                    "async process terminated successfully but should have set is_ready"
                )
            )


async def local_ws_server_async(is_ready):
    """Sets up a WithTestServer, with some DummySuccess shim to make it happy
    even without a proper runner, and run the IPC to the other thread."""

    unittest_backing = WithTestServer()
    await unittest_backing.asyncSetUp()

    class DummySuccess:
        # so that we don't need to go through another class to mock ._outcome.result._excinfo
        result = property(lambda self: self)

        _excinfo = None

    unittest_backing._outcome = DummySuccess()

    while_tests_run = asyncio.Future()
    loop = asyncio.get_event_loop()
    # Indicate readiness by sending a thread safe callback...
    is_ready.set_result(
        lambda: loop.call_soon_threadsafe(while_tests_run.set_result, None)
    )
    # ... and wait for that callback.
    await while_tests_run

    await unittest_backing.asyncTearDown()
