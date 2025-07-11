from django.http import JsonResponse
from telethon.errors import (
    ChannelInvalidError,
    ChannelPrivateError,
    RPCError,
    UsernameNotOccupiedError,
)
from telethon.tl.functions.channels import GetFullChannelRequest


class DataChannel:
    async def get_channel_data(self, client, entity):
        try:
            full = await client(GetFullChannelRequest(entity))
            channel_id = entity.id
            status = 'active'
            last_message_id = full.full_chat.read_inbox_max_id
            return {
                'channel_id': channel_id,
                'status': status,
                'last_message_id': last_message_id
            }
        except (
                ChannelInvalidError,
                ChannelPrivateError,
                UsernameNotOccupiedError) as e:
            return JsonResponse({
                'status': 'error',
                'error': 'Channel not found or was closed',
                'details': str(e)},
                status=400)

        except RPCError as e:
            return JsonResponse({
                'status': 'error',
                'error': 'Telegram RPC error',
                'details': str(e)},
                status=500)
