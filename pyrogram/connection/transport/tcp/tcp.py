#  Pyrogram - Telegram MTProto API Client Library for Python
#  Copyright (C) 2017-present Dan <https://github.com/delivrance>
#
#  This file is part of Pyrogram.
#
#  Pyrogram is free software: you can redistribute it and/or modify
#  it under the terms of the GNU Lesser General Public License as published
#  by the Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.
#
#  Pyrogram is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU Lesser General Public License for more details.
#
#  You should have received a copy of the GNU Lesser General Public License
#  along with Pyrogram.  If not, see <http://www.gnu.org/licenses/>.

import asyncio
import ipaddress
import logging
import socket
from concurrent.futures import ThreadPoolExecutor

import socks

log = logging.getLogger(__name__)


class TCP:
    TIMEOUT = 10

    def __init__(self, ipv6: bool, proxy: dict):
        self.socket = None

        self.reader = None
        self.writer = None

        self.lock = asyncio.Lock()
        self.loop = asyncio.get_event_loop()

        self.proxy = proxy

        self.ipv6 = ipv6
        self.address = None

        if proxy:
            hostname = proxy.get("hostname")

            try:
                ip_address = ipaddress.ip_address(hostname)
            except ValueError:
                self.socket = socks.socksocket(socket.AF_INET)
            else:
                if isinstance(ip_address, ipaddress.IPv6Address):
                    self.socket = socks.socksocket(socket.AF_INET6)
                else:
                    self.socket = socks.socksocket(socket.AF_INET)

            self.socket.set_proxy(
                proxy_type=getattr(socks, proxy.get("scheme").upper()),
                addr=hostname,
                port=proxy.get("port", None),
                username=proxy.get("username", None),
                password=proxy.get("password", None),
            )

            self.socket.settimeout(TCP.TIMEOUT)

            log.info("Using proxy %s", hostname)
        else:
            self.socket = socket.socket(socket.AF_INET6 if ipv6 else socket.AF_INET)

            self.socket.setblocking(False)

    async def connect(self, address: tuple):
        self.address = address
        if self.proxy:
            with ThreadPoolExecutor(1) as executor:
                await self.loop.run_in_executor(executor, self.socket.connect, address)
        else:
            try:
                await asyncio.wait_for(
                    asyncio.get_event_loop().sock_connect(self.socket, address),
                    TCP.TIMEOUT,
                )
            except (
                asyncio.TimeoutError
            ):  # Re-raise as TimeoutError. asyncio.TimeoutError is deprecated in 3.11
                raise TimeoutError("Connection timed out")

        self.reader, self.writer = await asyncio.open_connection(sock=self.socket)

    async def close(self):
        try:
            if self.writer is not None:
                self.writer.close()
                await asyncio.wait_for(self.writer.wait_closed(), TCP.TIMEOUT)
        except Exception as e:
            log.info("Close exception: %s %s", type(e).__name__, e)

    async def send(self, data: bytes):
        async with self.lock:
            for _ in (1, 2):
                try:
                    if self.writer is not None:
                        self.writer.write(data)
                        await self.writer.drain()
                except RuntimeError as e:
                    rec = await self.recon()
                    if rec is True:
                        log.info("TCP successfully reconnected, reason: %s %s", type(e).__name__, e)
                        continue  # try to send again
                    else:
                        log.info("TCP reconnect error: %s %s", type(rec).__name__, rec)
                        raise OSError(rec)
                except Exception as e:
                    log.info("Send exception: %s %s", type(e).__name__, e)
                    raise OSError(e)
                break

    async def recon(self):
        try:
            # replace the socket
            self.socket, self.reader, self.writer = None, None, None
            self.socket = socket.socket(socket.AF_INET6 if self.ipv6 else socket.AF_INET)
            self.socket.setblocking(False)
            # connect the new socket
            await self.connect(self.address)
            return True
        except Exception as e:
            log.info("ReConnect TCP exception: %s %s", type(e).__name__, e)
            return e

    async def recv(self, length: int = 0):
        data = b""

        if self.reader is None:
            slept = 0
            while self.reader is None:
                # TCP reconnect going on currently
                if slept >= TCP.TIMEOUT:
                    return None
                await asyncio.sleep(1)
                slept += 1

        while len(data) < length:
            try:
                chunk = await asyncio.wait_for(
                    self.reader.read(length - len(data)), TCP.TIMEOUT
                )
            except (OSError, asyncio.TimeoutError):
                return None
            else:
                if chunk:
                    data += chunk
                else:
                    return None

        return data
