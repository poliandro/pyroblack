#  pyroblack - Telegram MTProto API Client Library for Python
#  Copyright (C) 2017-present Dan <https://github.com/delivrance>
#  Copyright (C) 2022-present Mayuri-Chan <https://github.com/Mayuri-Chan>
#  Copyright (C) 2024-present eyMarv <https://github.com/eyMarv>
#
#  This file is part of pyroblack.
#
#  pyroblack is free software: you can redistribute it and/or modify
#  it under the terms of the GNU Lesser General Public License as published
#  by the Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.
#
#  pyroblack is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU Lesser General Public License for more details.
#
#  You should have received a copy of the GNU Lesser General Public License
#  along with pyroblack.  If not, see <http://www.gnu.org/licenses/>.

import asyncio
import functools
import inspect
import logging
import os
import platform
import re
import shutil
import sys
import io
import math
from concurrent.futures.thread import ThreadPoolExecutor
from datetime import datetime, timedelta
from functools import lru_cache
from hashlib import sha256
from importlib import import_module
from io import StringIO, BytesIO
from mimetypes import MimeTypes
from pathlib import Path
from typing import Union, List, Optional, Callable, AsyncGenerator, Type, Tuple, BinaryIO

import pyrogram
from pyrogram import types
from pyrogram import StopTransmission, Client
from pyrogram import __version__, __license__
from pyrogram import enums
from pyrogram import raw
from pyrogram import utils
from pyrogram.crypto import aes
from pyrogram.errors import CDNFileHashMismatch
from pyrogram.errors import (
    SessionPasswordNeeded,
    VolumeLocNotFound,
    ChannelPrivate,
    ChannelInvalid,
    BadRequest,
    AuthBytesInvalid,
    FloodWait,
    FloodPremiumWait,
    PersistentTimestampInvalid,
    PersistentTimestampOutdated,
    CDNFileHashMismatch,
    AuthKeyError
)
from pyrogram.handlers.handler import Handler
from pyrogram.methods import Methods
from pyrogram.session import Auth, Session
from pyrogram.storage import FileStorage, MemoryStorage, Storage
from pyrogram.types import User, TermsOfService
from pyrogram.utils import ainput, run_sync
from .connection import Connection
from .connection.transport import TCP, TCPAbridged
from .dispatcher import Dispatcher
from .file_id import FileId, FileType, ThumbnailSource
from .mime_types import mime_types
from .parser import Parser
from .session.internals import MsgId
from pyrogram.session import Session, Auth
from pyrogram.utils import run_sync

log = logging.getLogger(__name__)

# --- Constants ---
DOWNLOAD_CHUNK_SIZE = 1024 * 1024  # 1MB chunk size for GetFile requests
CONCURRENT_DOWNLOAD_THRESHOLD = 20 * 1024 * 1024 # 20 MB


# --- New Worker Function ---
async def download_worker(
    session: Session,
    request_queue: asyncio.Queue,
    result_queue: asyncio.Queue,
    location: raw.base.InputFileLocation,
    file_id_obj: FileId, # Pass the original FileId object for CDN info
    main_session_getter: Callable, # Function to get the main client session if needed
    client_invoke: Callable # Client's invoke method for auth transfer/CDN reupload
):
    """Worker task to download a specific chunk."""
    while True:
        task_info = await request_queue.get()
        if task_info is None:
            # Sentinel value received, exit worker
            request_queue.task_done()
            break

        part_index, offset, limit = task_info
        log.debug(f"Worker {session.dc_id}/{id(session)} starting part {part_index} (offset {offset})")

        cdn_redirect = None
        cdn_session = None

        for attempt in range(3): # Retry logic for transient errors
            try:
                # --- Initial GetFile Attempt ---
                r = await session.invoke(
                    raw.functions.upload.GetFile(
                        location=location, offset=offset, limit=limit
                    ),
                    sleep_threshold=15, # Shorter sleep for potentially faster parts
                )

                # --- Handle Standard Download ---
                if isinstance(r, raw.types.upload.File):
                    log.debug(f"Worker {session.dc_id}/{id(session)} got part {part_index} directly (size {len(r.bytes)})")
                    await result_queue.put((part_index, r.bytes))
                    request_queue.task_done()
                    break # Success for this part

                # --- Handle CDN Redirect ---
                elif isinstance(r, raw.types.upload.FileCdnRedirect):
                    log.debug(f"Worker {session.dc_id}/{id(session)} got CDN redirect for part {part_index} to DC {r.dc_id}")
                    cdn_redirect = r
                    # Need a CDN session
                    # Reuse existing if possible (complex) or create new one
                    cdn_session = Session(
                        session.client, # Use the client instance from the parent session
                        cdn_redirect.dc_id,
                        await Auth(session.client, cdn_redirect.dc_id, await session.client.storage.test_mode()).create(),
                        await session.client.storage.test_mode(),
                        is_media=True,
                        is_cdn=True,
                    )
                    await cdn_session.start()

                    # --- CDN Fetch Loop ---
                    while True:
                        log.debug(f"Worker {cdn_session.dc_id}/{id(cdn_session)} requesting CDN part {part_index} (offset {offset})")
                        r2 = await cdn_session.invoke(
                            raw.functions.upload.GetCdnFile(
                                file_token=cdn_redirect.file_token,
                                offset=offset,
                                limit=limit,
                            )
                        )

                        if isinstance(r2, raw.types.upload.CdnFileReuploadNeeded):
                            log.warning(f"Worker {cdn_session.dc_id}/{id(cdn_session)} needs CDN re-upload for part {part_index}")
                            try:
                                # Use the *original* session connected to the file's DC
                                # or the main client session to reupload
                                source_session_for_reupload = session # Assume original session can do it
                                await source_session_for_reupload.invoke(
                                     raw.functions.upload.ReuploadCdnFile(
                                         file_token=cdn_redirect.file_token,
                                         request_token=r2.request_token,
                                     )
                                 )
                                # Retry fetching from CDN after re-upload
                                continue
                            except VolumeLocNotFound:
                                log.error(f"Volume not found during CDN re-upload for part {part_index}")
                                raise # Propagate error
                            except Exception as e:
                                log.error(f"Error during CDN re-upload: {e}")
                                raise

                        # --- Decrypt and Verify CDN Chunk ---
                        encrypted_chunk = r2.bytes
                        decrypted_chunk = aes.ctr256_decrypt(
                            encrypted_chunk,
                            cdn_redirect.encryption_key,
                            bytearray(
                                cdn_redirect.encryption_iv[:-4]
                                + (offset // 16).to_bytes(4, "big")
                            ),
                        )

                        # Verification (Requires access to main client invoke potentially)
                        try:
                            hashes = await client_invoke( # Use main client invoke for this
                                raw.functions.upload.GetCdnFileHashes(
                                    file_token=cdn_redirect.file_token, offset=offset
                                )
                            )
                            for i, h in enumerate(hashes):
                                cdn_sub_chunk = decrypted_chunk[
                                    h.limit * i : h.limit * (i + 1)
                                ]
                                CDNFileHashMismatch.check(
                                    h.hash == sha256(cdn_sub_chunk).digest(),
                                    f"CDN hash mismatch part {part_index}, sub {i}",
                                )
                            log.debug(f"CDN hashes verified for part {part_index}")
                        except Exception as e:
                            log.error(f"CDN hash verification failed for part {part_index}: {e}")
                            # Decide whether to retry or fail
                            raise CDNFileHashMismatch from e


                        log.debug(f"Worker {cdn_session.dc_id}/{id(cdn_session)} got CDN part {part_index} (size {len(decrypted_chunk)})")
                        await result_queue.put((part_index, decrypted_chunk))
                        request_queue.task_done()
                        break # Break CDN fetch loop (success)
                    break # Break main retry loop (success via CDN)

            except (FloodWait, FloodPremiumWait) as e:
                log.warning(f"Worker {session.dc_id}/{id(session)} hit flood wait ({e.value}s) for part {part_index}, sleeping...")
                await asyncio.sleep(e.value + 1)
                # Continue to the next attempt in the retry loop
            except (AuthKeyError, VolumeLocNotFound) as e:
                 log.error(f"Worker {session.dc_id}/{id(session)} failed part {part_index} with unrecoverable error: {e}")
                 # Signal failure - how depends on overall error handling strategy
                 # For now, just log and the part won't arrive in result_queue
                 request_queue.task_done() # Mark task as done even on failure
                 raise # Re-raise to potentially cancel other tasks
            except Exception as e:
                log_func = log.warning if attempt < 2 else log.error
                log_func(
                    f"Worker {session.dc_id}/{id(session)} failed part {part_index} (attempt {attempt+1}/3): {e}",
                    exc_info=log.level <= logging.DEBUG # Show traceback if debug level
                )
                if attempt >= 2:
                     request_queue.task_done() # Mark task as done on final failure
                     raise # Re-raise to potentially cancel other tasks
                await asyncio.sleep(1 * (attempt + 1)) # Exponential backoff
            finally:
                 if cdn_session:
                     await cdn_session.stop()
                     cdn_session = None # Ensure cleanup

        else: # Else block executes if the loop finished without break (i.e., all retries failed)
             log.error(f"Worker {session.dc_id}/{id(session)} ultimately failed to download part {part_index}")
             # Error already raised in the loop


# --- New Writer Task ---
async def writer_task(
    result_queue: asyncio.Queue,
    file: Union[BinaryIO, io.BytesIO],
    file_total_parts: int,
    file_size: int,
    is_in_memory: bool,
    chunk_size: int,
    progress: Callable = None,
    progress_args: tuple = (),
    loop: asyncio.AbstractEventLoop = None, # Need the loop for run_in_executor
    executor = None # Need executor for run_in_executor
):
    """Consumes downloaded chunks and writes them sequentially."""
    next_expected_part = 0
    received_chunks = {}
    bytes_written = 0

    while next_expected_part < file_total_parts:
        try:
            # Wait indefinitely if needed, but add timeout for robustness?
            part_index, chunk = await result_queue.get()
        except Exception as e:
             log.error(f"Writer task error receiving from queue: {e}")
             raise # Propagate error

        log.debug(f"Writer received part {part_index}")
        received_chunks[part_index] = chunk

        # Write consecutive chunks
        while next_expected_part in received_chunks:
            chunk_to_write = received_chunks.pop(next_expected_part)
            chunk_len = len(chunk_to_write)
            log.debug(f"Writer writing part {next_expected_part} (size {chunk_len})")

            try:
                if is_in_memory:
                    file.write(chunk_to_write)
                else:
                    # Use run_sync for disk I/O
                    await run_sync(file.write, chunk_to_write)
            except Exception as e:
                 log.error(f"Writer task failed during file write for part {next_expected_part}: {e}")
                 raise # Propagate error


            bytes_written += chunk_len
            next_expected_part += 1
            result_queue.task_done() # Mark task as processed *after* writing

            # --- Progress Reporting ---
            if progress:
                current_bytes = min(bytes_written, file_size) if file_size else bytes_written
                total_bytes = file_size
                try:
                    func = functools.partial(
                        progress, current_bytes, total_bytes, *progress_args
                    )
                    if inspect.iscoroutinefunction(progress):
                        await func()
                    elif loop and executor: # Ensure loop and executor are available
                         # Use run_in_executor for sync progress callbacks
                        await loop.run_in_executor(executor, func)
                    else:
                        # Fallback or warning if executor unavailable
                         log.warning("Executor not available for sync progress callback")
                         func() # Run synchronously (potential blocking)
                except StopTransmission:
                     log.info("Download transmission stopped by progress callback.")
                     raise # Propagate StopTransmission
                except Exception as e:
                     log.warning(f"Progress callback error: {e}", exc_info=True)


    log.debug("Writer task finished writing all parts.")
    # Final progress update?
    if progress and bytes_written != (min(bytes_written, file_size) if file_size else bytes_written):
         # Call progress one last time if the last chunk pushed it over file_size
         current_bytes = min(bytes_written, file_size) if file_size else bytes_written
         total_bytes = file_size
         try:
            func = functools.partial(
                progress, current_bytes, total_bytes, *progress_args
            )
            if inspect.iscoroutinefunction(progress): await func()
            elif loop and executor: await loop.run_in_executor(executor, func)
            else: func()
         except Exception: pass # Ignore final progress errors

class Client(Methods):
    """pyroblack Client, the main means for interacting with Telegram.

    Parameters:
        name (``str``):
            A name for the client, e.g.: "my_account".

        api_id (``int`` | ``str``, *optional*):
            The *api_id* part of the Telegram API key, as integer or string.
            E.g.: 12345 or "12345".

        api_hash (``str``, *optional*):
            The *api_hash* part of the Telegram API key, as string.
            E.g.: "0123456789abcdef0123456789abcdef".

        app_version (``str``, *optional*):
            Application version.
            Defaults to "pyroblack x.y.z".

        device_model (``str``, *optional*):
            Device model.
            Defaults to *platform.python_implementation() + " " + platform.python_version()*.

        system_version (``str``, *optional*):
            Operating System version.
            Defaults to *platform.system() + " " + platform.release()*.

        lang_code (``str``, *optional*):
            Code of the language used on the client, in ISO 639-1 standard.
            Defaults to "en".

        system_lang_code (``str``, *optional*):
            Code of the language used on the system.
            Defaults to "en-US".

        lang_pack (``str``, *optional*):
            Internal parameter.
            Defaults to "".

        ipv6 (``bool``, *optional*):
            Pass True to connect to Telegram using IPv6.
            Defaults to False (IPv4).

        alt_port (``bool``, *optional*):
            Pass True to connect to Telegram using alternative port (5222).
            Defaults to False (443).

        proxy (``dict``, *optional*):
            The Proxy settings as dict.
            E.g.: *dict(scheme="socks5", hostname="11.22.33.44", port=1234, username="user", password="pass")*.
            The *username* and *password* can be omitted if the proxy doesn't require authorization.

        test_mode (``bool``, *optional*):
            Enable or disable login to the test servers.
            Only applicable for new sessions and will be ignored in case previously created sessions are loaded.
            Defaults to False.

        bot_token (``str``, *optional*):
            Pass the Bot API token to create a bot session, e.g.: "123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11"
            Only applicable for new sessions.

        session_string (``str``, *optional*):
            Pass a session string to load the session from a session string.
            Do you want a .session file? Use ``in_memory=False``,
            for in-memory use ``in_memory=True``.

        is_telethon_string (``bool``, *optional*):
            ``True`` if your provided session_string is in the telethon format.
            Requires ``session_string`` to be filled.

        in_memory (``bool``, *optional*):
            Pass True to start an in-memory session that will be discarded as soon as the client stops.
            In order to reconnect again using an in-memory session without having to login again, you can use
            :meth:`~pyrogram.Client.export_session_string` before stopping the client to get a session string you can
            pass to the ``session_string`` parameter.
            Defaults to False.

        storage (:obj:`~pyrogram.storage.Storage`, *optional*):
            Custom session storage.

        phone_number (``str``, *optional*):
            Pass the phone number as string (with the Country Code prefix included) to avoid entering it manually.
            Only applicable for new sessions.

        phone_code (``str``, *optional*):
            Pass the phone code as string (for test numbers only) to avoid entering it manually.
            Only applicable for new sessions.

        password (``str``, *optional*):
            Pass the Two-Step Verification password as string (if required) to avoid entering it manually.
            Only applicable for new sessions.

        workers (``int``, *optional*):
            Number of maximum concurrent workers for handling incoming updates.
            Defaults to ``min(32, os.cpu_count() + 4)``.

        workdir (``str``, *optional*):
            Define a custom working directory.
            The working directory is the location in the filesystem where pyroblack will store the session files.
            Defaults to the parent directory of the main script.

        plugins (``dict``, *optional*):
            Smart Plugins settings as dict, e.g.: *dict(root="plugins")*.

        parse_mode (:obj:`~pyrogram.enums.ParseMode`, *optional*):
            Set the global parse mode of the client. By default, texts are parsed using both Markdown and HTML styles.
            You can combine both syntaxes together.

        no_updates (``bool``, *optional*):
            Pass True to disable incoming updates.
            When updates are disabled the client can't receive messages or other updates.
            Useful for batch programs that don't need to deal with updates.
            Defaults to False (updates enabled and received).

        skip_updates (``bool``, *optional*):
            Pass True to skip pending updates that arrived while the client was offline.
            Defaults to True.

        takeout (``bool``, *optional*):
            Pass True to let the client use a takeout session instead of a normal one, implies *no_updates=True*.
            Useful for exporting Telegram data. Methods invoked inside a takeout session (such as get_chat_history,
            download_media, ...) are less prone to throw FloodWait exceptions.
            Only available for users, bots will ignore this parameter.
            Defaults to False (normal session).

        sleep_threshold (``int``, *optional*):
            Set a sleep threshold for flood wait exceptions happening globally in this client instance, below which any
            request that raises a flood wait will be automatically invoked again after sleeping for the required amount
            of time. Flood wait exceptions requiring higher waiting times will be raised.
            Defaults to 10 seconds.

        hide_password (``bool``, *optional*):
            Pass True to hide the password when typing it during the login.
            Defaults to False, because ``getpass`` (the library used) is known to be problematic in some
            terminal environments.

        max_concurrent_transmissions (``int``, *optional*):
            Set the maximum amount of concurrent transmissions (uploads & downloads).
            A value that is too high may result in network related issues.
            Defaults to 500.

        upload_boost (``bool``, *optional*):
            Make pyroblack use more parallel connections for file uploads.
            As far as your network allows it, you will get better upload speeds.
            On slow networks, this may result in network related issues.
            Default: False.

        init_params (``raw.types.JsonObject``, *optional*):
            Additional initConnection parameters.
            Defaults to None.

        max_message_cache_size (``int``, *optional*):
            Set the maximum size of the message cache.
            Defaults to 10000.

        client_platform (:obj:`~pyrogram.enums.ClientPlatform`, *optional*):
            The platform where this client is running.
            Defaults to 'other'
    """

    APP_VERSION = f"pyroblack {__version__}"
    DEVICE_MODEL = f"{platform.python_implementation()} {platform.python_version()}"
    SYSTEM_VERSION = f"{platform.system()} {platform.release()}"

    LANG_CODE = "en"
    SYSTEM_LANG_CODE = "en-US"
    LANG_PACK = ""

    PARENT_DIR = Path(sys.argv[0]).parent

    INVITE_LINK_RE = re.compile(
        r"^(?:https?://)?(?:www\.)?(?:t(?:elegram)?\.(?:org|me|dog)/(?:joinchat/|\+))([\w-]+)$"
    )
    WORKERS = min(32, (os.cpu_count() or 0) + 4)  # os.cpu_count() can be None
    WORKDIR = PARENT_DIR

    # Interval of seconds in which the updates watchdog will kick in
    UPDATES_WATCHDOG_INTERVAL = 10 * 60

    MAX_CONCURRENT_TRANSMISSIONS = 1
    MAX_MESSAGE_CACHE_SIZE = 10000

    mimetypes = MimeTypes()
    mimetypes.readfp(StringIO(mime_types))

    def __init__(
        self,
        name: str,
        api_id: Union[int, str] = None,
        api_hash: str = None,
        app_version: str = APP_VERSION,
        device_model: str = DEVICE_MODEL,
        system_version: str = SYSTEM_VERSION,
        lang_code: str = LANG_CODE,
        system_lang_code: str = SYSTEM_LANG_CODE,
        lang_pack: str = LANG_PACK,
        ipv6: bool = False,
        alt_port: bool = False,
        proxy: dict = None,
        test_mode: bool = False,
        bot_token: str = None,
        session_string: str = None,
        is_telethon_string: bool = False,
        in_memory: bool = None,
        storage: Storage = None,
        phone_number: str = None,
        phone_code: str = None,
        password: str = None,
        workers: int = WORKERS,
        workdir: str = WORKDIR,
        plugins: dict = None,
        parse_mode: "enums.ParseMode" = enums.ParseMode.DEFAULT,
        no_updates: bool = None,
        skip_updates: bool = True,
        takeout: bool = None,
        sleep_threshold: int = Session.SLEEP_THRESHOLD,
        hide_password: bool = False,
        max_concurrent_transmissions: int = MAX_CONCURRENT_TRANSMISSIONS,
        upload_boost: bool = False,
        init_params: raw.types.JsonObject = None,
        max_message_cache_size: int = MAX_MESSAGE_CACHE_SIZE,
        client_platform: "enums.ClientPlatform" = enums.ClientPlatform.OTHER,
        connection_factory: Type[Connection] = Connection,
        protocol_factory: Type[TCP] = TCPAbridged,
    ):
        super().__init__()

        self.name = name
        self.api_id = int(api_id) if api_id else None
        self.api_hash = api_hash
        self.app_version = app_version
        self.device_model = device_model
        self.system_version = system_version
        self.lang_code = lang_code.lower()
        self.system_lang_code = system_lang_code
        self.lang_pack = lang_pack.lower()
        self.ipv6 = ipv6
        self.alt_port = alt_port
        self.proxy = proxy
        self.test_mode = test_mode
        self.bot_token = bot_token
        self.session_string = session_string
        self.is_telethon_string = is_telethon_string
        self.in_memory = in_memory
        self.phone_number = phone_number
        self.phone_code = phone_code
        self.password = password
        self.workers = workers
        self.workdir = Path(workdir)
        self.plugins = plugins
        self.parse_mode = parse_mode
        self.no_updates = no_updates
        self.skip_updates = skip_updates
        self.takeout = takeout
        self.sleep_threshold = sleep_threshold
        self.hide_password = hide_password
        self.max_concurrent_transmissions = max_concurrent_transmissions
        self.upload_boost = upload_boost
        self.init_params = init_params
        self.max_message_cache_size = max_message_cache_size
        self.client_platform = client_platform
        self.connection_factory = connection_factory
        self.protocol_factory = protocol_factory

        self.executor = ThreadPoolExecutor(self.workers, thread_name_prefix="Handler")

        if storage:
            self.storage = storage
        elif self.in_memory:
            self.storage = MemoryStorage(
                self.name, self.session_string, self.is_telethon_string
            )
        else:
            self.storage = FileStorage(
                self.name, self.workdir, self.session_string, self.is_telethon_string
            )

        self.dispatcher = Dispatcher(self)

        self.rnd_id = MsgId

        self.parser = Parser(self)

        self.session = None

        self.media_sessions = {}
        self.media_sessions_lock = asyncio.Lock()

        self.save_file_semaphore = asyncio.Semaphore(self.max_concurrent_transmissions)
        self.get_file_semaphore = asyncio.Semaphore(self.max_concurrent_transmissions)

        self.is_connected = None
        self.is_initialized = None

        self.takeout_id = None

        self.disconnect_handler = None
        self.invoke_err_handler = None

        self.me: Optional[User] = None

        self.message_cache = Cache(self.max_message_cache_size)

        # Sometimes, for some reason, the server will stop sending updates and will only respond to pings.
        # This watchdog will invoke updates.GetState in order to wake up the server and enable it sending updates again
        # after some idle time has been detected.
        self.updates_watchdog_task = None
        self.updates_watchdog_event = asyncio.Event()
        self.last_update_time = datetime.now()
        self.listeners = {
            listener_type: [] for listener_type in pyrogram.enums.ListenerTypes
        }
        self.loop = asyncio.get_event_loop()

    def __enter__(self):
        return self.start()

    def __exit__(self, *args):
        try:
            self.stop()
        except ConnectionError:
            pass

    async def __aenter__(self):
        return await self.start()

    async def __aexit__(self, *args):
        try:
            await self.stop()
        except ConnectionError:
            pass

    async def updates_watchdog(self):
        while True:
            try:
                await asyncio.wait_for(
                    self.updates_watchdog_event.wait(), self.UPDATES_WATCHDOG_INTERVAL
                )
            except asyncio.TimeoutError:
                pass
            else:
                break

            if datetime.now() - self.last_update_time > timedelta(
                seconds=self.UPDATES_WATCHDOG_INTERVAL
            ):
                await self.invoke(raw.functions.updates.GetState())

    async def authorize(self) -> User:
        if self.bot_token:
            return await self.sign_in_bot(self.bot_token)

        print(f"Welcome to pyroblack (version {__version__})")
        print(
            f"pyroblack is free software and comes with ABSOLUTELY NO WARRANTY. Licensed\n"
            f"under the terms of the {__license__}.\n"
        )

        while True:
            try:
                if not self.phone_number:
                    while True:
                        value = await ainput("Enter phone number or bot token: ")

                        if not value:
                            continue

                        confirm = (
                            await ainput(f'Is "{value}" correct? (y/N): ')
                        ).lower()

                        if confirm == "y":
                            break

                    if ":" in value:
                        self.bot_token = value
                        return await self.sign_in_bot(value)
                    else:
                        self.phone_number = value

                sent_code = await self.send_code(self.phone_number)
            except BadRequest as e:
                print(e.MESSAGE)
                self.phone_number = None
                self.bot_token = None
            else:
                break

        sent_code_descriptions = {
            enums.SentCodeType.APP: "Telegram app",
            enums.SentCodeType.SMS: "SMS",
            enums.SentCodeType.CALL: "phone call",
            enums.SentCodeType.FLASH_CALL: "phone flash call",
            enums.SentCodeType.FRAGMENT_SMS: "Fragment SMS",
            enums.SentCodeType.EMAIL_CODE: "email code",
        }

        print(
            f"The confirmation code has been sent via {sent_code_descriptions[sent_code.type]}"
        )

        while True:
            if not self.phone_code:
                self.phone_code = await ainput("Enter confirmation code: ")

            try:
                signed_in = await self.sign_in(
                    self.phone_number, sent_code.phone_code_hash, self.phone_code
                )
            except BadRequest as e:
                print(e.MESSAGE)
                self.phone_code = None
            except SessionPasswordNeeded as e:
                print(e.MESSAGE)

                while True:
                    print("Password hint: {}".format(await self.get_password_hint()))

                    if not self.password:
                        self.password = await ainput(
                            "Enter password (empty to recover): ",
                            hide=self.hide_password,
                        )

                    try:
                        if not self.password:
                            confirm = await ainput("Confirm password recovery (y/n): ")

                            if confirm == "y":
                                email_pattern = await self.send_recovery_code()
                                print(
                                    f"The recovery code has been sent to {email_pattern}"
                                )

                                while True:
                                    recovery_code = await ainput(
                                        "Enter recovery code: "
                                    )

                                    try:
                                        return await self.recover_password(
                                            recovery_code
                                        )
                                    except BadRequest as e:
                                        print(e.MESSAGE)
                                    except Exception as e:
                                        log.exception(e)
                                        raise
                            else:
                                self.password = None
                        else:
                            return await self.check_password(self.password)
                    except BadRequest as e:
                        print(e.MESSAGE)
                        self.password = None
            else:
                break

        if isinstance(signed_in, User):
            return signed_in

        while True:
            first_name = await ainput("Enter first name: ")
            last_name = await ainput("Enter last name (empty to skip): ")

            try:
                signed_up = await self.sign_up(
                    self.phone_number, sent_code.phone_code_hash, first_name, last_name
                )
            except BadRequest as e:
                print(e.MESSAGE)
            else:
                break

        if isinstance(signed_in, TermsOfService):
            print("\n" + signed_in.text + "\n")
            await self.accept_terms_of_service(signed_in.id)

        return signed_up

    def set_parse_mode(self, parse_mode: Optional["enums.ParseMode"]):
        """Set the parse mode to be used globally by the client.

        When setting the parse mode with this method, all other methods having a *parse_mode* parameter will follow the
        global value by default.

        Parameters:
            parse_mode (:obj:`~pyrogram.enums.ParseMode`):
                By default, texts are parsed using both Markdown and HTML styles.
                You can combine both syntaxes together.

        Example:
            .. code-block:: python

                from pyrogram import enums

                # Default combined mode: Markdown + HTML
                await app.send_message("me", "1. **markdown** and <i>html</i>")

                # Force Markdown-only, HTML is disabled
                app.set_parse_mode(enums.ParseMode.MARKDOWN)
                await app.send_message("me", "2. **markdown** and <i>html</i>")

                # Force HTML-only, Markdown is disabled
                app.set_parse_mode(enums.ParseMode.HTML)
                await app.send_message("me", "3. **markdown** and <i>html</i>")

                # Disable the parser completely
                app.set_parse_mode(enums.ParseMode.DISABLED)
                await app.send_message("me", "4. **markdown** and <i>html</i>")

                # Bring back the default combined mode
                app.set_parse_mode(enums.ParseMode.DEFAULT)
                await app.send_message("me", "5. **markdown** and <i>html</i>")
        """

        self.parse_mode = parse_mode

    async def fetch_peers(
        self, peers: List[Union[raw.types.User, raw.types.Chat, raw.types.Channel]]
    ) -> bool:
        is_min = False
        parsed_peers = []
        usernames = []

        for peer in peers:
            if getattr(peer, "min", False):
                is_min = True
                continue

            username = None
            phone_number = None

            if isinstance(peer, raw.types.User):
                peer_id = peer.id
                access_hash = peer.access_hash
                username = (
                    peer.username.lower()
                    if peer.username
                    else peer.usernames[0].username.lower() if peer.usernames else None
                )
                if peer.usernames is not None and len(peer.usernames) > 1:
                    for uname in peer.usernames:
                        usernames.append((peer_id, uname.username.lower()))
                phone_number = peer.phone
                peer_type = "bot" if peer.bot else "user"
            elif isinstance(peer, (raw.types.Chat, raw.types.ChatForbidden)):
                peer_id = -peer.id
                access_hash = 0
                peer_type = "group"
            elif isinstance(peer, raw.types.Channel):
                peer_id = utils.get_channel_id(peer.id)
                access_hash = peer.access_hash
                username = (
                    peer.username.lower()
                    if peer.username
                    else peer.usernames[0].username.lower() if peer.usernames else None
                )
                if peer.usernames is not None and len(peer.usernames) > 1:
                    for uname in peer.usernames:
                        usernames.append((peer_id, uname.username.lower()))
                peer_type = "channel" if peer.broadcast else "supergroup"
            elif isinstance(peer, raw.types.ChannelForbidden):
                peer_id = utils.get_channel_id(peer.id)
                access_hash = peer.access_hash
                peer_type = "channel" if peer.broadcast else "supergroup"
            else:
                continue

            parsed_peers.append(
                (peer_id, access_hash, peer_type, username, phone_number)
            )

        await self.storage.update_peers(parsed_peers)
        await self.storage.update_usernames(usernames)

        return is_min

    async def handle_updates(self, updates):
        self.last_update_time = datetime.now()

        if isinstance(updates, (raw.types.Updates, raw.types.UpdatesCombined)):
            is_min = any(
                (
                    await self.fetch_peers(updates.users),
                    await self.fetch_peers(updates.chats),
                )
            )

            users = {u.id: u for u in updates.users}
            chats = {c.id: c for c in updates.chats}

            for update in updates.updates:
                channel_id = getattr(
                    getattr(getattr(update, "message", None), "peer_id", None),
                    "channel_id",
                    None,
                ) or getattr(update, "channel_id", None)

                pts = getattr(update, "pts", None)
                pts_count = getattr(update, "pts_count", None)

                if pts and not self.skip_updates:
                    await self.storage.update_state(
                        (
                            utils.get_channel_id(channel_id) if channel_id else 0,
                            pts,
                            None,
                            updates.date,
                            updates.seq,
                        )
                    )

                if isinstance(update, raw.types.UpdateChannelTooLong):
                    log.info(update)

                if isinstance(update, raw.types.UpdateNewChannelMessage) and is_min:
                    message = update.message

                    if not isinstance(message, raw.types.MessageEmpty):
                        try:
                            diff = await self.invoke(
                                raw.functions.updates.GetChannelDifference(
                                    channel=await self.resolve_peer(
                                        utils.get_channel_id(channel_id)
                                    ),
                                    filter=raw.types.ChannelMessagesFilter(
                                        ranges=[
                                            raw.types.MessageRange(
                                                min_id=update.message.id,
                                                max_id=update.message.id,
                                            )
                                        ]
                                    ),
                                    pts=pts - pts_count,
                                    limit=pts,
                                    force=False,
                                )
                            )
                        except (
                            ChannelPrivate,
                            PersistentTimestampOutdated,
                            PersistentTimestampInvalid,
                        ):
                            pass
                        else:
                            if not isinstance(
                                diff, raw.types.updates.ChannelDifferenceEmpty
                            ):
                                if diff:
                                    users.update({u.id: u for u in diff.users})
                                    chats.update({c.id: c for c in diff.chats})

                self.dispatcher.updates_queue.put_nowait((update, users, chats))
        elif isinstance(
            updates, (raw.types.UpdateShortMessage, raw.types.UpdateShortChatMessage)
        ):
            if not self.skip_updates:
                await self.storage.update_state(
                    (0, updates.pts, None, updates.date, None)
                )

            diff = await self.invoke(
                raw.functions.updates.GetDifference(
                    pts=updates.pts - updates.pts_count, date=updates.date, qts=-1
                )
            )

            if diff.new_messages:
                self.dispatcher.updates_queue.put_nowait(
                    (
                        raw.types.UpdateNewMessage(
                            message=diff.new_messages[0],
                            pts=updates.pts,
                            pts_count=updates.pts_count,
                        ),
                        {u.id: u for u in diff.users},
                        {c.id: c for c in diff.chats},
                    )
                )
            else:
                if diff.other_updates:  # The other_updates list can be empty
                    self.dispatcher.updates_queue.put_nowait(
                        (diff.other_updates[0], {}, {})
                    )
        elif isinstance(updates, raw.types.UpdateShort):
            self.dispatcher.updates_queue.put_nowait((updates.update, {}, {}))
        elif isinstance(updates, raw.types.UpdatesTooLong):
            log.info(updates)

    async def recover_gaps(self) -> Tuple[int, int]:
        states = await self.storage.update_state()

        message_updates_counter = 0
        other_updates_counter = 0

        if not states:
            log.info("No states found, skipping recovery.")
            return (message_updates_counter, other_updates_counter)

        for state in states:
            id, local_pts, _, local_date, _ = state

            prev_pts = 0

            while True:
                try:
                    diff = await self.invoke(
                        raw.functions.updates.GetChannelDifference(
                            channel=await self.resolve_peer(id),
                            filter=raw.types.ChannelMessagesFilterEmpty(),
                            pts=local_pts,
                            limit=10000,
                            force=False,
                        )
                        if id < 0
                        else raw.functions.updates.GetDifference(
                            pts=local_pts, date=local_date, qts=0
                        )
                    )
                except (
                    ChannelPrivate,
                    ChannelInvalid,
                    PersistentTimestampOutdated,
                    PersistentTimestampInvalid,
                ):
                    break

                if isinstance(diff, raw.types.updates.DifferenceEmpty):
                    break
                elif isinstance(diff, raw.types.updates.DifferenceTooLong):
                    break
                elif isinstance(diff, raw.types.updates.Difference):
                    local_pts = diff.state.pts
                elif isinstance(diff, raw.types.updates.DifferenceSlice):
                    local_pts = diff.intermediate_state.pts
                    local_date = diff.intermediate_state.date

                    if prev_pts == local_pts:
                        break

                    prev_pts = local_pts
                elif isinstance(diff, raw.types.updates.ChannelDifferenceEmpty):
                    break
                elif isinstance(diff, raw.types.updates.ChannelDifferenceTooLong):
                    break
                elif isinstance(diff, raw.types.updates.ChannelDifference):
                    local_pts = diff.pts

                users = {i.id: i for i in diff.users}
                chats = {i.id: i for i in diff.chats}

                for message in diff.new_messages:
                    message_updates_counter += 1
                    self.dispatcher.updates_queue.put_nowait(
                        (
                            raw.types.UpdateNewMessage(
                                message=message, pts=local_pts, pts_count=-1
                            ),
                            users,
                            chats,
                        )
                    )

                for update in diff.other_updates:
                    other_updates_counter += 1
                    self.dispatcher.updates_queue.put_nowait((update, users, chats))

                if isinstance(
                    diff,
                    (raw.types.updates.Difference, raw.types.updates.ChannelDifference),
                ):
                    break

            await self.storage.update_state(id)

        log.info(
            "Recovered %s messages and %s updates.",
            message_updates_counter,
            other_updates_counter,
        )
        return (message_updates_counter, other_updates_counter)

    async def load_session(self):
        await self.storage.open()

        session_empty = any(
            [
                await self.storage.test_mode() is None,
                await self.storage.auth_key() is None,
                await self.storage.user_id() is None,
                await self.storage.is_bot() is None,
            ]
        )

        if session_empty:
            if not self.api_id or not self.api_hash:
                raise AttributeError(
                    "The API key is required for new authorizations. "
                    "More info: https://eyMarv.github.io/pyroblack-docs/start/auth"
                )

            await self.storage.api_id(self.api_id)

            await self.storage.dc_id(2)
            await self.storage.date(0)

            await self.storage.test_mode(self.test_mode)
            await self.storage.auth_key(
                await Auth(
                    self, await self.storage.dc_id(), await self.storage.test_mode()
                ).create()
            )
            await self.storage.user_id(None)
            await self.storage.is_bot(None)
        else:
            # Needed for migration from storage v2 to v3
            if not await self.storage.api_id():
                if self.api_id:
                    await self.storage.api_id(self.api_id)
                else:
                    while True:
                        try:
                            value = int(
                                await ainput("Enter the api_id part of the API key: ")
                            )

                            if value <= 0:
                                print("Invalid value")
                                continue

                            confirm = (
                                await ainput(f'Is "{value}" correct? (y/N): ')
                            ).lower()

                            if confirm == "y":
                                await self.storage.api_id(value)
                                break
                        except Exception as e:
                            print(e)

    def is_excluded(self, exclude, module):
        for e in exclude:
            if module == e or module.startswith(e + "."):
                return True
        return False

    def load_plugins(self):
        if self.plugins:
            plugins = self.plugins.copy()

            for option in ["include", "exclude"]:
                if plugins.get(option, []):
                    plugins[option] = [
                        (i.split()[0], i.split()[1:] or None)
                        for i in self.plugins[option]
                    ]
        else:
            return

        if plugins.get("enabled", True):
            root = plugins["root"]
            include = plugins.get("include", [])
            exclude = plugins.get("exclude", [])

            exclude_plugins = []
            exclude_handlers = {}

            if exclude:
                for path, handler in exclude:
                    module_path = os.path.join(
                        root.replace(".", "/"), path.replace(".", "/")
                    )
                    if handler is None:
                        exclude_plugins.append(
                            module_path.replace("/", ".").replace("\\", ".")
                        )
                    else:
                        exclude_handlers[
                            module_path.replace("/", ".").replace("\\", ".")
                        ] = handler

            count = 0

            if not include:
                for current_root, dirnames, filenames in os.walk(
                    root.replace(".", "/")
                ):
                    namespace = current_root.replace("/", ".").replace("\\", ".")
                    if "__pycache__" in namespace:
                        continue
                    if namespace in exclude_plugins:
                        log.warning(
                            '[%s] [LOAD] Ignoring namespace "%s"', self.name, namespace
                        )
                        continue
                    else:
                        for filename in filenames:
                            if filename.endswith(".py"):
                                module_path = namespace + "." + filename[:-3]
                                if module_path in exclude_plugins:
                                    log.warning(
                                        '[%s] [LOAD] Ignoring namespace "%s"',
                                        self.name,
                                        module_path,
                                    )
                                    continue
                                else:
                                    module = import_module(module_path)

                                    for name in vars(module).keys():

                                        # noinspection PyBroadException
                                        try:
                                            for handler, group in getattr(
                                                module, name
                                            ).handlers:
                                                if isinstance(
                                                    handler, Handler
                                                ) and isinstance(group, int):

                                                    if (
                                                        module_path in exclude_handlers
                                                        and name
                                                        in exclude_handlers[module_path]
                                                    ):
                                                        exclude_handlers[
                                                            module_path
                                                        ].remove(name)
                                                        log.warning(
                                                            '[{}] [LOAD] Ignoring function "{}" from group {} in "{}"'.format(
                                                                self.name,
                                                                name,
                                                                group,
                                                                module_path,
                                                            )
                                                        )
                                                        continue

                                                    self.add_handler(handler, group)

                                                    log.info(
                                                        '[{}] [LOAD] {}("{}") in group {} from "{}"'.format(
                                                            self.name,
                                                            type(handler).__name__,
                                                            name,
                                                            group,
                                                            module_path,
                                                        )
                                                    )

                                                    count += 1
                                        except Exception as e:
                                            pass
            else:
                for path, handlers in include:
                    module_path = root.replace("/", ".").replace("\\", ".") + "." + path
                    if self.is_excluded(exclude_plugins, module_path):
                        log.warning(
                            '[%s] [LOAD] Ignoring namespace "%s"',
                            self.name,
                            module_path,
                        )
                        continue

                    warn_non_existent_functions = True

                    try:
                        module = import_module(module_path)
                    except ImportError:
                        log.warning(
                            '[%s] [LOAD] Ignoring non-existent module "%s"',
                            self.name,
                            module_path,
                        )
                        continue

                    if "__path__" in dir(module):
                        for current_root, _, filenames in os.walk(
                            module_path.replace(".", "/")
                        ):
                            namespace = current_root.replace("/", ".").replace(
                                "\\", "."
                            )
                            if "__pycache__" in namespace:
                                continue
                            if namespace in exclude_plugins:
                                log.warning(
                                    '[%s] [LOAD] Ignoring namespace "%s"',
                                    self.name,
                                    namespace,
                                )
                                continue
                            else:
                                for filename in filenames:
                                    if filename.endswith(".py"):
                                        module_path = namespace + "." + filename[:-3]
                                        if module_path in exclude_plugins:
                                            log.warning(
                                                '[%s] [LOAD] Ignoring namespace "%s"',
                                                self.name,
                                                module_path,
                                            )
                                            continue
                                        else:
                                            module = import_module(module_path)
                                            for name in vars(module).keys():
                                                # noinspection PyBroadException
                                                try:
                                                    for handler, group in getattr(
                                                        module, name
                                                    ).handlers:
                                                        if isinstance(
                                                            handler, Handler
                                                        ) and isinstance(group, int):

                                                            if (
                                                                module_path
                                                                in exclude_handlers
                                                                and name
                                                                in exclude_handlers[
                                                                    module_path
                                                                ]
                                                            ):
                                                                exclude_handlers[
                                                                    module_path
                                                                ].remove(name)
                                                                log.warning(
                                                                    '[{}] [LOAD] Ignoring function "{}" from group {} in "{}"'.format(
                                                                        self.name,
                                                                        name,
                                                                        group,
                                                                        module_path,
                                                                    )
                                                                )
                                                                continue

                                                            self.add_handler(
                                                                handler, group
                                                            )

                                                            log.info(
                                                                '[{}] [LOAD] {}("{}") in group {} from "{}"'.format(
                                                                    self.name,
                                                                    type(
                                                                        handler
                                                                    ).__name__,
                                                                    name,
                                                                    group,
                                                                    module_path,
                                                                )
                                                            )

                                                            count += 1
                                                except Exception as e:
                                                    pass

                    if handlers is None:
                        handlers = vars(module).keys()
                        warn_non_existent_functions = False

                    for name in handlers:
                        # noinspection PyBroadException
                        try:
                            for handler, group in getattr(module, name).handlers:
                                if isinstance(handler, Handler) and isinstance(
                                    group, int
                                ):
                                    if (
                                        module_path in exclude_handlers
                                        and name in exclude_handlers[module_path]
                                    ):
                                        exclude_handlers[module_path].remove(name)
                                        log.warning(
                                            '[{}] [LOAD] Ignoring function "{}" from group {} in "{}"'.format(
                                                self.name, name, group, module_path
                                            )
                                        )
                                        continue
                                    self.add_handler(handler, group)

                                    log.info(
                                        '[{}] [LOAD] {}("{}") in group {} from "{}"'.format(
                                            self.name,
                                            type(handler).__name__,
                                            name,
                                            group,
                                            module_path,
                                        )
                                    )

                                    count += 1
                        except Exception:
                            if warn_non_existent_functions:
                                log.warning(
                                    '[{}] [LOAD] Ignoring non-existent function "{}" from "{}"'.format(
                                        self.name, name, module_path
                                    )
                                )

            for module in exclude_handlers:
                for handler in exclude_handlers[module]:
                    log.warning(
                        '[{}] [LOAD] Ignoring non-existent function "{}" from "{}"'.format(
                            self.name, handler, module
                        )
                    )

            if count > 0:
                log.info(
                    '[{}] Successfully loaded {} plugin{} from "{}"'.format(
                        self.name, count, "s" if count > 1 else "", root
                    )
                )
            else:
                log.warning('[%s] No plugin loaded from "%s"', self.name, root)

    async def handle_download(self, packet):
        (
            file_id_obj, # Assume this is a FileId object now
            directory,
            file_name,
            in_memory,
            file_size,
            progress,
            progress_args,
        ) = packet

        if not isinstance(file_id_obj, FileId):
             log.error("handle_download expects a FileId object as the first element.")
             return None # Or raise appropriate error

        if file_size == 0:
             log.warning(f"File size for {file_id_obj} is 0, cannot determine concurrency. Falling back to sequential.")
             # Consider trying a GetFile first to get size? Or just fail?
             # For now, let's attempt sequential using the old logic (if available)
             # or just fail if sequential isn't easily available.
             # Simplified: return None or raise error.
             log.error("Cannot download file with reported size 0 using concurrent method.")
             return None
             # Alternatively, call a sequential version here if you keep it.

        # --- Determine Concurrency Settings ---
        if file_size <= CONCURRENT_DOWNLOAD_THRESHOLD:
            # Rule 1: <= 20 MB -> 5 connections, 2 workers/connection
            pool_size = 5
            workers_per_session = 2
        else:
            # Rule 2: > 20 MB -> 2 connections, 4 workers/connection
            pool_size = 2
            workers_per_session = 4
        total_workers = pool_size * workers_per_session

        log.info(f"Concurrent download starting for {file_name} ({utils.humanbytes(file_size)}): "
                 f"{pool_size} connections, {workers_per_session} workers/conn ({total_workers} total)")


        # --- Prepare File Destination ---
        os.makedirs(directory, exist_ok=True) if not in_memory else None
        temp_file_path = (
            os.path.abspath(re.sub(r"\\", "/", os.path.join(directory, file_name)))
            + ".temp"
        )
        file_handle = io.BytesIO() if in_memory else open(temp_file_path, "wb")

        # --- Calculate Parts ---
        file_total_parts = math.ceil(file_size / DOWNLOAD_CHUNK_SIZE)

        # --- Build InputFileLocation ---
        # (Copied and adapted from the original get_file)
        file_type = file_id_obj.file_type
        if file_type == FileType.CHAT_PHOTO:
            if file_id_obj.chat_id > 0:
                peer = raw.types.InputPeerUser(user_id=file_id_obj.chat_id, access_hash=file_id_obj.chat_access_hash)
            else:
                peer = (raw.types.InputPeerChat(chat_id=-file_id_obj.chat_id) if file_id_obj.chat_access_hash == 0
                        else raw.types.InputPeerChannel(channel_id=utils.get_channel_id(file_id_obj.chat_id), access_hash=file_id_obj.chat_access_hash))
            location = raw.types.InputPeerPhotoFileLocation(peer=peer, photo_id=file_id_obj.media_id, big=file_id_obj.thumbnail_source == ThumbnailSource.CHAT_PHOTO_BIG)
        elif file_type == FileType.PHOTO:
            location = raw.types.InputPhotoFileLocation(id=file_id_obj.media_id, access_hash=file_id_obj.access_hash, file_reference=file_id_obj.file_reference, thumb_size=file_id_obj.thumbnail_size)
        else: # Document, Video, etc.
            location = raw.types.InputDocumentFileLocation(id=file_id_obj.media_id, access_hash=file_id_obj.access_hash, file_reference=file_id_obj.file_reference, thumb_size=file_id_obj.thumbnail_size)

        # --- Setup Queues ---
        request_queue = asyncio.Queue(maxsize=total_workers * 2) # Buffer slightly ahead
        result_queue = asyncio.Queue(maxsize=total_workers * 2) # Buffer results

        # --- Setup Sessions and Workers ---
        sessions = []
        worker_tasks = []
        original_dc_id = await self.storage.dc_id()
        target_dc_id = file_id_obj.dc_id
        test_mode = await self.storage.test_mode()
        auth_key = await self.storage.auth_key()
        exported_auth_bytes = None

        async with self.get_file_semaphore: # Use semaphore for overall download limiting
            try:
                # --- Auth Export (if needed) ---
                if target_dc_id != original_dc_id:
                    log.debug(f"Exporting auth from DC {original_dc_id} for DC {target_dc_id}")
                    exported_auth = await self.invoke(
                        raw.functions.auth.ExportAuthorization(dc_id=target_dc_id)
                    )
                    exported_auth_bytes = exported_auth.bytes
                    log.debug(f"Auth exported successfully (ID: {exported_auth.id})")


                # --- Create Session Pool ---
                for i in range(pool_size):
                    session_auth_key = (
                        await Auth(self, target_dc_id, test_mode).create()
                        if target_dc_id != original_dc_id
                        else auth_key
                    )
                    session = Session(
                        self, target_dc_id, session_auth_key, test_mode, is_media=True
                    )
                    sessions.append(session)

                # --- Start Sessions and Import Auth ---
                for session in sessions:
                    await session.start()
                    if exported_auth_bytes:
                        log.debug(f"Importing auth to session for DC {target_dc_id}")
                        await session.invoke(
                            raw.functions.auth.ImportAuthorization(
                                id=exported_auth.id, bytes=exported_auth_bytes
                            )
                        )
                        log.debug(f"Auth imported successfully to session {id(session)}")


                # --- Create Writer Task ---
                writer = asyncio.create_task(
                    writer_task(
                        result_queue,
                        file_handle,
                        file_total_parts,
                        file_size,
                        in_memory,
                        DOWNLOAD_CHUNK_SIZE,
                        progress,
                        progress_args,
                        self.loop, # Pass loop
                        self.executor # Pass executor
                    )
                )

                # --- Create Worker Tasks ---
                for i, session in enumerate(sessions):
                    for j in range(workers_per_session):
                        task = asyncio.create_task(
                            download_worker(
                                session,
                                request_queue,
                                result_queue,
                                location,
                                file_id_obj,
                                lambda: self.session, # Function to get main session if needed
                                self.invoke # Pass client's invoke method
                            )
                        )
                        worker_tasks.append(task)

                # --- Populate Request Queue ---
                log.debug(f"Populating request queue with {file_total_parts} parts...")
                for i in range(file_total_parts):
                    offset = i * DOWNLOAD_CHUNK_SIZE
                    limit = min(DOWNLOAD_CHUNK_SIZE, file_size - offset)
                    if limit <= 0: break # Should not happen if file_total_parts is correct
                    await request_queue.put((i, offset, limit))
                log.debug("Request queue populated.")

                # --- Add Sentinels for Workers ---
                for _ in worker_tasks:
                    await request_queue.put(None)

                # --- Wait for Workers ---
                log.debug("Waiting for workers to finish...")
                results = await asyncio.gather(*worker_tasks, return_exceptions=True)
                log.debug("Workers finished.")

                # Check for worker errors
                worker_failed = False
                for i, res in enumerate(results):
                    if isinstance(res, Exception) and not isinstance(res, asyncio.CancelledError):
                        log.error(f"Worker task {i} failed: {res}", exc_info=isinstance(res, Exception))
                        worker_failed = True
                if worker_failed:
                     # If a worker failed, cancel the writer and raise error
                     log.error("One or more workers failed. Cancelling download.")
                     writer.cancel()
                     raise Exception("Concurrent download failed due to worker error(s).") # Or a specific custom error

                # --- Signal and Wait for Writer ---
                log.debug("Waiting for writer task to finish...")
                await result_queue.join() # Wait for writer to process all items put *before* sentinel
                await result_queue.put(None) # Sentinel for writer
                await writer # Wait for writer task to exit cleanly
                log.debug("Writer task finished.")

            except (FloodWait, FloodPremiumWait) as e:
                 log.warning(f"Download stopped due to FloodWait: {e.value}s")
                 # Cleanup needs to happen in finally
                 raise e # Re-raise specific flood waits
            except StopTransmission:
                log.info("Download stopped by StopTransmission.")
                # Cleanup happens in finally
                raise
            except asyncio.CancelledError:
                 log.warning("Download cancelled.")
                 raise
            except Exception as e:
                log.error(f"Error during concurrent download setup or execution: {e}", exc_info=True)
                # Ensure cleanup happens in finally
                # Try to cancel any running tasks if they weren't awaited/gathered
                if not writer.done(): writer.cancel()
                for task in worker_tasks:
                    if not task.done(): task.cancel()
                raise # Re-raise the exception
            else:
                # --- Success Case: Finalize File ---
                if in_memory:
                    file_handle.name = file_name
                    file_handle.seek(0) # Rewind for reading
                    return file_handle
                else:
                    file_handle.close() # Close the temp file
                    file_path = os.path.splitext(temp_file_path)[0]
                    log.debug(f"Moving {temp_file_path} to {file_path}")
                    try:
                        await run_sync(shutil.move, temp_file_path, file_path)
                        return file_path
                    except Exception as e:
                         log.error(f"Failed to move temp file {temp_file_path} to {file_path}: {e}")
                         # Attempt to remove temp file if move failed
                         try: await run_sync(os.remove, temp_file_path)
                         except Exception: pass
                         raise # Re-raise the move error

            finally:
                # --- Cleanup ---
                log.debug("Stopping download sessions...")
                for session in sessions:
                    await session.stop()
                log.debug("Download sessions stopped.")

                # Ensure file handle is closed if not in memory and not returned
                if not in_memory and not 'file_path' in locals() and file_handle and not file_handle.closed:
                    log.debug("Closing file handle in finally block.")
                    file_handle.close()
                    # Attempt to remove temp file if download didn't complete successfully
                    if os.path.exists(temp_file_path):
                         log.debug(f"Removing incomplete temp file: {temp_file_path}")
                         try: await run_sync(os.remove, temp_file_path)
                         except Exception as e: log.warning(f"Failed to remove temp file {temp_file_path}: {e}")

    @lru_cache(maxsize=128)
    def guess_mime_type(self, filename: str) -> Optional[str]:
        return self.mimetypes.guess_type(filename)[0]

    @lru_cache(maxsize=128)
    def guess_extension(self, mime_type: str) -> Optional[str]:
        return self.mimetypes.guess_extension(mime_type)


class Cache:
    def __init__(self, capacity: int):
        self.capacity = capacity
        self.store = {}

    def __getitem__(self, key):
        return self.store.get(key, None)

    def __setitem__(self, key, value):
        if key in self.store:
            del self.store[key]

        self.store[key] = value

        if len(self.store) > self.capacity:
            for _ in range(self.capacity // 2 + 1):
                del self.store[next(iter(self.store))]
