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

from typing import Union

import pyrogram
from pyrogram import raw, types

from ..messages.inline_session import get_session


class PinChatMessage:
    async def pin_chat_message(
        self: "pyrogram.Client",
        chat_id: Union[int, str],
        message_id: int,
        disable_notification: bool = False,
        both_sides: bool = False,
        business_connection_id: str = None,
    ) -> "types.Message":
        """Pin a message in a group, channel or your own chat.
        You must be an administrator in the chat for this to work and must have the "can_pin_messages" admin right in
        the supergroup or "can_edit_messages" admin right in the channel.

        .. include:: /_includes/usable-by/users-bots.rst

        Parameters:
            chat_id (``int`` | ``str``):
                Unique identifier (int) or username (str) of the target chat.
                You can also use chat public link in form of *t.me/<username>* (str).

            message_id (``int``):
                Identifier of a message to pin.

            disable_notification (``bool``, *optional*):
                Pass True, if it is not necessary to send a notification to all chat members about the new pinned
                message. Notifications are always disabled in channels.

            both_sides (``bool``, *optional*):
                Pass True to pin the message for both sides (you and recipient).
                Applicable to private chats only. Defaults to False.

            business_connection_id (``str``, *optional*):
                Unique identifier of the business connection on behalf of which the message will be pinned.

        Returns:
            :obj:`~pyrogram.types.Message`: On success, the service message is returned.

        Example:
            .. code-block:: python

                # Pin with notification
                await app.pin_chat_message(chat_id, message_id)

                # Pin without notification
                await app.pin_chat_message(chat_id, message_id, disable_notification=True)
        """
        rpc = raw.functions.messages.UpdatePinnedMessage(
            peer=await self.resolve_peer(chat_id),
            id=message_id,
            silent=disable_notification or None,
            pm_oneside=not both_sides or None,
        )

        if business_connection_id:
            r = await self.invoke(
                raw.functions.InvokeWithBusinessConnection(
                    query=rpc, connection_id=business_connection_id
                )
            )
        else:
            r = await self.invoke(rpc)

        users = {u.id: u for u in r.users}
        chats = {c.id: c for c in r.chats}

        for i in r.updates:
            if isinstance(
                i,
                (
                    raw.types.UpdateNewMessage,
                    raw.types.UpdateNewChannelMessage,
                    raw.types.UpdateBotNewBusinessMessage,
                ),
            ):
                return await types.Message._parse(
                    self,
                    i.message,
                    users,
                    chats,
                    business_connection_id=business_connection_id,
                )
