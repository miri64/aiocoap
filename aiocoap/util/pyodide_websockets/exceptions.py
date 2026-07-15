# SPDX-FileCopyrightText: Christian Amsüss and the aiocoap contributors
#
# SPDX-License-Identifier: MIT


class WebSocketException(Exception):
    pass


class ConnectionClosed(WebSocketException):
    pass


class InvalidStatus(WebSocketException):
    # We never raise this, ws.py needs the type to catch an exception.
    pass
