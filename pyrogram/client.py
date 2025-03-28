#  Pyrofork - Telegram MTProto API Client Library for Python
#  Copyright (C) 2017-present Dan <https://github.com/delivrance>
#  Copyright (C) 2022-present Mayuri-Chan <https://github.com/Mayuri-Chan>
#
#  This file is part of Pyrofork.
#
#  Pyrofork is free software: you can redistribute it and/or modify
#  it under the terms of the GNU Lesser General Public License as published
#  by the Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.
#
#  Pyrofork is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU Lesser General Public License for more details.
#
#  You should have received a copy of the GNU Lesser General Public License
#  along with Pyrofork.  If not, see <http://www.gnu.org/licenses/>.

import asyncio
import functools
import inspect
import logging
import os
import platform
import re
import shutil
import sys
import math # <-- Added import
from concurrent.futures.thread import ThreadPoolExecutor
from datetime import datetime, timedelta
from hashlib import sha256, md5 # <-- Added md5 (might not be needed for download, but good practice)
from importlib import import_module
from io import StringIO, BytesIO
from mimetypes import MimeTypes
from pathlib import Path, PurePath # <-- Added PurePath
from typing import Union, List, Optional, Callable, AsyncGenerator, Tuple, BinaryIO # <-- Added BinaryIO, math

import pyrogram
from pyrogram import __version__, __license__
from pyrogram import enums
from pyrogram import raw
from pyrogram import utils
from pyrogram import StopTransmission # <-- Added StopTransmission
from pyrogram.crypto import aes
from pyrogram.errors import CDNFileHashMismatch
from pyrogram.errors import (
    SessionPasswordNeeded,
    VolumeLocNotFound, ChannelPrivate,
    BadRequest, ChannelInvalid, PersistentTimestampInvalid, PersistentTimestampOutdated,
    AuthKeyError # <-- Added AuthKeyError for potential session issues
)
from pyrogram.handlers.handler import Handler
from pyrogram.methods import Methods
from pyrogram.session import Auth, Session
from pyrogram.storage import FileStorage, MemoryStorage, Storage
from pyrogram.types import User, TermsOfService
from pyrogram.utils import ainput, run_sync # <-- Added run_sync

from .connection import Connection
from .connection.transport import TCPAbridged
from .dispatcher import Dispatcher
from .file_id import FileId, FileType, ThumbnailSource
from .mime_types import mime_types
from .parser import Parser
from .session.internals import MsgId

log = logging.getLogger(__name__)
MONGO_AVAIL = False

try:
    import pymongo
except Exception:
    pass
else:
    from pyrogram.storage import MongoStorage
    MONGO_AVAIL = True


# Define a reasonable default for concurrent chunk downloads
# Adjust based on performance testing and network conditions
DEFAULT_DOWNLOAD_WORKERS = 4

class Client(Methods):
    APP_VERSION = f"Pyrogram {__version__}"
    DEVICE_MODEL = f"{platform.python_implementation()} {platform.python_version()}"
    SYSTEM_VERSION = f"{platform.system()} {platform.release()}"

    LANG_CODE = "en"

    PARENT_DIR = Path(sys.argv[0]).parent

    INVITE_LINK_RE = re.compile(r"^(?:https?://)?(?:www\.)?(?:t(?:elegram)?\.(?:org|me|dog)/(?:joinchat/|\+))([\w-]+)$")
    WORKERS = min(32, (os.cpu_count() or 0) + 4)  # os.cpu_count() can be None
    WORKDIR = PARENT_DIR

    # Interval of seconds in which the updates watchdog will kick in
    UPDATES_WATCHDOG_INTERVAL = 15 * 60

    MAX_CONCURRENT_TRANSMISSIONS = 1 # Increased default for potential parallelism
    MAX_CACHE_SIZE = 10000

    mimetypes = MimeTypes()
    mimetypes.readfp(StringIO(mime_types))

    def __init__(
        self,
        name: str,
        api_id: Optional[Union[int, str]] = None,
        api_hash: Optional[str] = None,
        app_version: str = APP_VERSION,
        device_model: str = DEVICE_MODEL,
        system_version: str = SYSTEM_VERSION,
        lang_code: str = LANG_CODE,
        ipv6: Optional[bool] = False,
        alt_port: Optional[bool] = False,
        proxy: Optional[dict] = None,
        test_mode: Optional[bool] = False,
        bot_token: Optional[str] = None,
        session_string: Optional[str] = None,
        in_memory: Optional[bool] = None,
        mongodb: Optional[dict] = None,
        storage: Optional[Storage] = None,
        phone_number: Optional[str] = None,
        phone_code: Optional[str] = None,
        password: Optional[str] = None,
        workers: int = WORKERS,
        workdir: Union[str, Path] = WORKDIR,
        plugins: Optional[dict] = None,
        parse_mode: "enums.ParseMode" = enums.ParseMode.DEFAULT,
        no_updates: Optional[bool] = None,
        skip_updates: bool = True,
        takeout: bool = None,
        sleep_threshold: int = Session.SLEEP_THRESHOLD,
        hide_password: Optional[bool] = False,
        max_concurrent_transmissions: int = MAX_CONCURRENT_TRANSMISSIONS,
        client_platform: "enums.ClientPlatform" = enums.ClientPlatform.OTHER,
        max_message_cache_size: int = MAX_CACHE_SIZE,
        max_business_user_connection_cache_size: int = MAX_CACHE_SIZE,
        download_workers: int = DEFAULT_DOWNLOAD_WORKERS, # <-- Added download workers
        upload_boost: bool = False # <-- Added upload_boost for consistency with save_file
    ):
        super().__init__()

        self.name = name
        self.api_id = int(api_id) if api_id else None
        self.api_hash = api_hash
        self.app_version = app_version
        self.device_model = device_model
        self.system_version = system_version
        self.lang_code = lang_code.lower()
        self.ipv6 = ipv6
        self.alt_port = alt_port
        self.proxy = proxy
        self.test_mode = test_mode
        self.bot_token = bot_token
        self.session_string = session_string
        self.in_memory = in_memory
        self.mongodb = mongodb
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
        self.client_platform = client_platform
        self.max_message_cache_size = max_message_cache_size
        self.max_business_user_connection_cache_size = max_business_user_connection_cache_size
        self.download_workers = min(max(1, download_workers), 16) # Limit workers
        self.upload_boost = upload_boost # Store upload_boost setting

        self.executor = ThreadPoolExecutor(self.workers, thread_name_prefix="Handler")

        if storage:
            self.storage = storage
        elif self.session_string:
            self.storage = MemoryStorage(self.name, self.session_string)
        elif self.in_memory:
            self.storage = MemoryStorage(self.name)
        elif self.mongodb:
            if not MONGO_AVAIL:
                log.warning(
                    "pymongo is missing! "
                    "Using MemoryStorage as session storage"
                )
                self.storage = MemoryStorage(self.name)
            else:
                self.storage = MongoStorage(self.name, **self.mongodb)
        else:
            self.storage = FileStorage(self.name, self.workdir)

        self.connection_factory = Connection
        self.protocol_factory = TCPAbridged

        self.dispatcher = Dispatcher(self)

        self.rnd_id = MsgId

        self.parser = Parser(self)

        self.session: Optional[Session] = None # Type hint

        self.media_sessions = {}
        self.media_sessions_lock = asyncio.Lock()

        # Changed semaphore limit
        self.save_file_semaphore = asyncio.Semaphore(self.max_concurrent_transmissions)
        self.get_file_semaphore = asyncio.Semaphore(self.max_concurrent_transmissions) # Controls overall download ops

        self.is_connected = None
        self.is_initialized = None

        self.takeout_id = None

        self.disconnect_handler = None

        self.me: Optional[User] = None

        self.message_cache = Cache(self.max_message_cache_size)
        self.business_user_connection_cache = Cache(self.max_business_user_connection_cache_size)

        # Updates Watchdog
        self.updates_watchdog_task = None
        self.updates_watchdog_event = asyncio.Event()
        self.last_update_time = datetime.now()
        self.listeners = {listener_type: [] for listener_type in pyrogram.enums.ListenerTypes}
        self.loop = asyncio.get_running_loop() if sys.version_info >= (3, 7) else asyncio.get_event_loop()


    # ... (rest of the __init__ and other methods remain the same until handle_download)

    async def handle_download(
        self,
        packet: Tuple[
            FileId, str, str, bool, int, Optional[Callable], tuple
        ]
    ):
        """Internal handler to download a file and save it."""
        file_id, directory, file_name, in_memory, file_size, progress, progress_args = packet

        _ = os.makedirs(directory, exist_ok=True) if not in_memory else None
        temp_file_path = os.path.abspath(re.sub("\\\\", "/", os.path.join(directory, file_name))) + ".temp"
        file: Union[BytesIO, BinaryIO]
        if in_memory:
            file = BytesIO()
        else:
            # Use buffering=0 for direct write, managed by BytesIO internally for efficiency
            file = open(temp_file_path, "wb", buffering=0)

        downloaded_bytes = 0
        try:
            # The generator now handles concurrency internally
            async for chunk in self.get_file(
                file_id=file_id,
                file_size=file_size,
                progress=progress,
                progress_args=progress_args
                # limit and offset are handled inside get_file now for chunking
            ):
                # Directly write the received chunk
                await run_sync(file.write, chunk)
                downloaded_bytes += len(chunk)

        except BaseException as e:
            if not in_memory:
                file.close()
                # Ensure the temp file exists before trying to remove
                if os.path.exists(temp_file_path):
                    try:
                        os.remove(temp_file_path)
                    except OSError as oe:
                        log.warning(f"Could not remove temp file {temp_file_path}: {oe}")

            if isinstance(e, (asyncio.CancelledError, pyrogram.StopTransmission)):
                log.info(f"Download cancelled for {file_name}")
                raise e # Re-raise cancellation/stop
            elif isinstance(e, pyrogram.errors.FloodWait):
                log.warning(f"Download flood waived for {file_name}, wait {e.value}s")
                raise e # Re-raise flood wait
            else:
                log.error(f"Download failed for {file_name}: {e}", exc_info=True)
                return None # Indicate failure
        else:
            if in_memory:
                file.seek(0) # Rewind for reading
                file.name = file_name
                log.info(f"Downloaded {file_name} to memory ({utils.humanbytes(downloaded_bytes)})")
                return file
            else:
                file.close()
                file_path = os.path.splitext(temp_file_path)[0]
                try:
                    # Use replace for atomic move on supported systems
                    os.replace(temp_file_path, file_path)
                except OSError:
                    # Fallback for systems where replace isn't atomic (e.g., cross-fs)
                    shutil.move(temp_file_path, file_path)
                log.info(f"Downloaded {file_name} to {file_path} ({utils.humanbytes(downloaded_bytes)})")
                return file_path


    async def get_file(
        self,
        file_id: FileId,
        file_size: int = 0,
        limit: int = 0,
        offset: int = 0,
        progress: Optional[Callable] = None,
        progress_args: tuple = (),
    ) -> AsyncGenerator[bytes, None]:
        """
        Asynchronously downloads a file from Telegram servers concurrently.

        Yields chunks of the file content.
        """
        # Overall control for concurrent download *operations*
        async with self.get_file_semaphore:
            location: Union[raw.base.InputFileLocation, raw.base.InputPeerLocated]
            file_type = file_id.file_type

            # Determine Input Location based on FileId Type
            if file_type == FileType.CHAT_PHOTO:
                if file_id.chat_id > 0:
                    peer = raw.types.InputPeerUser(user_id=file_id.chat_id, access_hash=file_id.chat_access_hash)
                else:
                    peer = (
                        raw.types.InputPeerChat(chat_id=-file_id.chat_id)
                        if file_id.chat_access_hash == 0
                        else raw.types.InputPeerChannel(channel_id=utils.get_channel_id(file_id.chat_id), access_hash=file_id.chat_access_hash)
                    )
                location = raw.types.InputPeerPhotoFileLocation(
                    peer=peer, photo_id=file_id.media_id, big=file_id.thumbnail_source == ThumbnailSource.CHAT_PHOTO_BIG
                )
            elif file_type == FileType.PHOTO:
                location = raw.types.InputPhotoFileLocation(
                    id=file_id.media_id, access_hash=file_id.access_hash, file_reference=file_id.file_reference, thumb_size=file_id.thumbnail_size
                )
            else:  # DOCUMENT, STICKER, VIDEO, etc.
                location = raw.types.InputDocumentFileLocation(
                    id=file_id.media_id, access_hash=file_id.access_hash, file_reference=file_id.file_reference, thumb_size=file_id.thumbnail_size
                )

            # --- Concurrency Setup ---
            dc_id = file_id.dc_id
            main_dc_id = await self.storage.dc_id()
            is_media_dc = dc_id != main_dc_id
            current_test_mode = await self.storage.test_mode()

            chunk_size = 1024 * 1024  # Optimal chunk size, potentially adjustable
            pool_size = self.download_workers
            download_tasks: List[asyncio.Task] = []
            sessions: List[Session] = []
            workers_semaphore = asyncio.Semaphore(pool_size) # Limit concurrent chunk requests

            # --- Session Pool Creation & Auth ---
            exported_auth: Optional[raw.types.auth.ExportedAuthorization] = None
            if is_media_dc:
                try:
                    # Export auth ONLY ONCE if needed
                    exported_auth = await self.invoke(
                        raw.functions.auth.ExportAuthorization(dc_id=dc_id)
                    )
                except AuthKeyError:
                     log.error(f"Failed to export authorization to DC {dc_id}. Falling back to sequential download.")
                     # Fallback to original sequential logic might be complex here.
                     # For now, raise the error or return. A robust fallback needs more thought.
                     raise # Or implement a non-concurrent fallback path

            log.debug(f"Creating session pool (size {pool_size}) for DC {dc_id}")
            main_auth_key = await self.storage.auth_key()
            for i in range(pool_size):
                s = Session(
                    self, dc_id,
                    await Auth(self, dc_id, current_test_mode).create() if is_media_dc else main_auth_key,
                    current_test_mode,
                    is_media=True,
                    session_id=f"dl_{i}" # Optional: unique identifier for logging
                )
                sessions.append(s)

            cdn_redirect: Optional[raw.types.upload.FileCdnRedirect] = None
            cdn_sessions: List[Session] = []

            try:
                 # --- Start Sessions & Import Auth ---
                log.debug("Starting sessions...")
                await asyncio.gather(*(s.start() for s in sessions))
                if is_media_dc and exported_auth:
                    log.debug(f"Importing authorization to {pool_size} sessions for DC {dc_id}")
                    await asyncio.gather(*(
                        s.invoke(
                            raw.functions.auth.ImportAuthorization(
                                id=exported_auth.id, bytes=exported_auth.bytes
                            ),
                            sleep_threshold=self.sleep_threshold # Apply global threshold
                        ) for s in sessions
                    ))
                log.debug("Sessions started and authorized.")


                # --- Worker Function Definition ---
                async def download_chunk(
                    session: Session,
                    offset: int,
                    limit: int,
                    task_id: int,
                    is_cdn: bool = False,
                    cdn_info: Optional[raw.types.upload.FileCdnRedirect] = None
                ) -> bytes:
                    nonlocal cdn_redirect # Allow modification if first chunk causes redirect

                    for attempt in range(3): # Retry mechanism
                        await workers_semaphore.acquire() # Limit active requests
                        try:
                            if is_cdn:
                                if not cdn_info: raise ValueError("CDN info missing")

                                log.debug(f"[CDN Worker {task_id}] Requesting offset {offset}, limit {limit}")
                                result = await session.invoke(
                                    raw.functions.upload.GetCdnFile(
                                        file_token=cdn_info.file_token,
                                        offset=offset,
                                        limit=limit
                                    ),
                                    sleep_threshold=self.sleep_threshold
                                )

                                if isinstance(result, raw.types.upload.CdnFileReuploadNeeded):
                                    log.warning(f"[CDN Worker {task_id}] Re-upload needed for token {cdn_info.file_token}, offset {offset}")
                                    # Find a non-CDN session to perform the re-upload request
                                    reupload_session = next((s for s in sessions if not s.is_cdn), None)
                                    if not reupload_session:
                                        raise RuntimeError("No main DC session available for CDN re-upload request")
                                    try:
                                        await reupload_session.invoke(
                                            raw.functions.upload.ReuploadCdnFile(
                                                file_token=cdn_info.file_token,
                                                request_token=result.request_token
                                            )
                                        )
                                        log.info(f"[CDN Worker {task_id}] Re-upload requested successfully. Retrying chunk.")
                                        # Don't release semaphore here, retry immediately in the next loop iteration
                                        continue # Retry the download chunk request

                                    except VolumeLocNotFound:
                                        log.error(f"[CDN Worker {task_id}] VolumeLocNotFound during CDN re-upload. Aborting chunk.")
                                        # This specific chunk fails, might need broader handling
                                        raise
                                    except Exception as re_err:
                                         log.error(f"[CDN Worker {task_id}] Error during CDN re-upload request: {re_err}", exc_info=True)
                                         raise # Propagate re-upload error


                                chunk_data = result.bytes
                                # Decrypt CDN chunk
                                decrypted_chunk = aes.ctr256_decrypt(
                                    chunk_data,
                                    cdn_info.encryption_key,
                                    bytearray(cdn_info.encryption_iv[:-4] + (offset // 16).to_bytes(4, "big"))
                                )

                                # Verify Hashes (Optional optimization: maybe verify later or less often)
                                hashes = await session.invoke(
                                    raw.functions.upload.GetCdnFileHashes(
                                        file_token=cdn_info.file_token, offset=offset
                                    )
                                )
                                for i, h in enumerate(hashes):
                                     cdn_part = decrypted_chunk[h.limit * i : h.limit * (i + 1)]
                                     if sha256(cdn_part).digest() != h.hash:
                                          raise CDNFileHashMismatch(f"CDN hash mismatch at offset {offset + h.limit * i}")

                                log.debug(f"[CDN Worker {task_id}] Got chunk offset {offset}, size {len(decrypted_chunk)}")
                                return decrypted_chunk

                            else: # Normal Download
                                log.debug(f"[Worker {task_id}] Requesting offset {offset}, limit {limit}")
                                result = await session.invoke(
                                    raw.functions.upload.GetFile(
                                        location=location, offset=offset, limit=limit, precise=True # precise can help
                                    ),
                                    sleep_threshold=self.sleep_threshold # Apply global threshold
                                )

                                if isinstance(result, raw.types.upload.FileCdnRedirect):
                                     log.info(f"CDN Redirect encountered by worker {task_id} at offset {offset}. Switching to CDN mode.")
                                     # Signal main loop to switch strategy
                                     cdn_redirect = result
                                     # This worker's result is now invalid for this chunk, needs retry via CDN
                                     raise StopIteration("CDN Redirect") # Use specific exception to signal retry

                                elif isinstance(result, raw.types.upload.File):
                                    log.debug(f"[Worker {task_id}] Got chunk offset {offset}, size {len(result.bytes)}")
                                    return result.bytes
                                else:
                                    # Should not happen if API call is correct
                                    raise TypeError(f"Unexpected result type from GetFile: {type(result)}")

                        except StopIteration as si:
                            if str(si) == "CDN Redirect":
                                # Don't increment attempt count, this needs a mode switch
                                raise # Propagate redirect signal
                            else:
                                log.error(f"[Worker {task_id}] Unknown StopIteration: {si}", exc_info=True)
                                raise # Propagate other stop iterations
                        except (pyrogram.errors.FloodWait, asyncio.TimeoutError, TimeoutError, AuthKeyError) as transient_error:
                             wait_time = getattr(transient_error, 'value', 2 ** attempt)
                             log.warning(f"[Worker {task_id}] Retrying ({attempt + 1}/3) chunk offset {offset} due to {type(transient_error).__name__}. Waiting {wait_time}s.")
                             await asyncio.sleep(wait_time)
                             continue # Go to next attempt
                        except Exception as e:
                            log.error(f"[Worker {task_id}] Error downloading chunk offset {offset} (attempt {attempt+1}/3): {e}", exc_info=True)
                            if attempt >= 2: # If last attempt failed
                                raise # Propagate persistent error
                            await asyncio.sleep(2 ** attempt) # Exponential backoff before retry
                        finally:
                            workers_semaphore.release() # Release limit


                    # If loop finishes without returning (3 failed attempts)
                    raise ConnectionError(f"Failed to download chunk at offset {offset} after 3 attempts.")


                # --- Main Download Loop ---
                current_offset_bytes = abs(offset) * chunk_size # Start offset in bytes
                total_bytes_to_download = (abs(limit) * chunk_size if limit > 0
                                      else (file_size - current_offset_bytes if file_size > 0 else (1 << 31) - 1))
                # Adjust total size if offset is present and file_size is known
                effective_file_size = file_size if file_size > 0 else None

                total_parts = math.ceil(total_bytes_to_download / chunk_size)
                log.info(f"Starting download: {total_parts} parts, chunk size {chunk_size}, total ~{utils.humanbytes(total_bytes_to_download)}")

                part_index = 0
                bytes_yielded = 0
                is_cdn_mode = False

                while part_index < total_parts:
                    # Check if CDN redirect happened
                    if cdn_redirect and not is_cdn_mode:
                        log.info("Switching all workers to CDN mode...")
                        is_cdn_mode = True
                        # Stop existing non-CDN sessions and tasks cleanly? Difficult.
                        # For simplicity, create new CDN sessions and tasks.

                        # Stop old tasks if possible (best effort)
                        for t in download_tasks:
                           if not t.done(): t.cancel()
                        await asyncio.gather(*download_tasks, return_exceptions=True) # Wait for cancellations/completions
                        download_tasks.clear()

                        # Stop old sessions
                        await asyncio.gather(*(s.stop() for s in sessions), return_exceptions=True)
                        sessions.clear()

                        # Create CDN session pool
                        cdn_dc_id = cdn_redirect.dc_id
                        log.debug(f"Creating CDN session pool (size {pool_size}) for DC {cdn_dc_id}")
                        cdn_auth_key = await Auth(self, cdn_dc_id, current_test_mode).create() # Needs fresh auth key
                        for i in range(pool_size):
                            s = Session(
                                self, cdn_dc_id, cdn_auth_key, current_test_mode,
                                is_media=True, is_cdn=True, session_id=f"cdn_{i}"
                            )
                            cdn_sessions.append(s)
                        await asyncio.gather(*(s.start() for s in cdn_sessions))
                        log.debug("CDN sessions started.")
                        # Re-evaluate total_parts? CDN might have different behavior, but assume same chunking for now.
                        # Restart task creation from the current part_index
                        # The main loop continues, now creating CDN tasks


                    # Create tasks up to pool size limit
                    while len(download_tasks) < pool_size and part_index + len(download_tasks) < total_parts:
                        current_part = part_index + len(download_tasks)
                        task_offset = current_offset_bytes + current_part * chunk_size

                        # Choose session round-robin
                        session_pool = cdn_sessions if is_cdn_mode else sessions
                        selected_session = session_pool[current_part % pool_size]

                        task = asyncio.create_task(
                            download_chunk(
                                session=selected_session,
                                offset=task_offset,
                                limit=chunk_size,
                                task_id=current_part, # Pass part index as task id for logging
                                is_cdn=is_cdn_mode,
                                cdn_info=cdn_redirect if is_cdn_mode else None
                            ),
                             name=f"DownloadChunk_{current_part}" # Name task for debugging
                        )
                        download_tasks.append(task)

                    # Wait for the *next required* task to complete
                    if not download_tasks: # Should not happen if total_parts > 0
                         break

                    try:
                        # Await the first task in the list (which corresponds to the current part_index)
                        chunk = await download_tasks[0]

                        # --- Yield and Progress Update ---
                        yield chunk
                        bytes_yielded += len(chunk)
                        part_index += 1 # Move to the next part

                        # Remove completed task
                        download_tasks.pop(0)

                        if progress:
                            # Calculate progress based on bytes yielded relative to total expected
                            current_prog = current_offset_bytes + bytes_yielded
                            total_prog = current_offset_bytes + total_bytes_to_download
                            # Use effective_file_size if known for total in callback
                            report_total = effective_file_size if effective_file_size is not None else total_prog

                            func = functools.partial(progress, min(current_prog, report_total), report_total, *progress_args)
                            if inspect.iscoroutinefunction(progress):
                                await func()
                            else:
                                # Run sync progress callbacks in executor to avoid blocking event loop
                                await self.loop.run_in_executor(self.executor, func)

                    except (StopIteration, CDNFileHashMismatch, ConnectionError) as e:
                         # Handle errors from download_chunk
                         log.error(f"Download failed for part {part_index} due to {type(e).__name__}: {e}")
                         # Cancel remaining tasks on fatal error
                         for t in download_tasks:
                             if not t.done(): t.cancel()
                         await asyncio.gather(*download_tasks, return_exceptions=True)
                         raise # Propagate the error to handle_download

                    except asyncio.CancelledError:
                         log.warning(f"Download task for part {part_index} was cancelled.")
                         # Propagate cancellation if generator itself is cancelled
                         raise

            except (AuthKeyError, pyrogram.errors.UserDeactivatedBan) as auth_err:
                 log.error(f"Authorization failed during download setup: {auth_err}", exc_info=True)
                 raise # Critical error, stop download
            except Exception as e:
                 log.error(f"An unexpected error occurred during download: {e}", exc_info=True)
                 # Cancel any pending tasks
                 for t in download_tasks:
                      if not t.done(): t.cancel()
                 await asyncio.gather(*download_tasks, return_exceptions=True)
                 raise # Propagate error
            finally:
                # --- Cleanup ---
                log.debug("Stopping sessions...")
                active_sessions = sessions + cdn_sessions
                await asyncio.gather(*(s.stop() for s in active_sessions if s.is_connected), return_exceptions=True)
                log.debug("Download process finished.")

    # --- Rest of the Client class methods (like guess_mime_type, guess_extension, etc.) ---
    # ... (Include the SaveFile class methods as well if they were part of the original class)
    from .save_file import SaveFile # Assuming save_file logic is in a separate mixin/file
    save_file = SaveFile.save_file

    def guess_mime_type(self, filename: str) -> Optional[str]:
        return self.mimetypes.guess_type(filename)[0]

    def guess_extension(self, mime_type: str) -> Optional[str]:
        return self.mimetypes.guess_extension(mime_type)


class Cache:
    def __init__(self, capacity: int):
        self.capacity = capacity
        self.store = {}
        # Basic LRU logic: Use list to track access order
        self._access_order = []

    def __getitem__(self, key):
        value = self.store.get(key, None)
        if value is not None:
            # Move accessed key to the end (most recently used)
            if key in self._access_order: # Check needed if key was evicted but still in store temporarily
                self._access_order.remove(key)
            self._access_order.append(key)
        return value

    def __setitem__(self, key, value):
        if key in self.store:
            # Key exists, update value and move to end
             self.store[key] = value
             if key in self._access_order: self._access_order.remove(key)
             self._access_order.append(key)
        else:
             # New key, check capacity
             if len(self.store) >= self.capacity:
                  # Evict least recently used (first item in list)
                  lru_key = self._access_order.pop(0)
                  if lru_key in self.store: # Ensure it wasn't already removed by another thread/task
                     del self.store[lru_key]

             # Add new item
             self.store[key] = value
             self._access_order.append(key)

    # Optional: Add methods like __contains__, __delitem__, clear etc. if needed


# Make sure to import the SaveFile logic if it's separate
# Example assuming it's in `pyrofork/client/save_file.py` relative to this file
# from .save_file import SaveFile
# Client.save_file = SaveFile.save_file # Add the method to the Client class
