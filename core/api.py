# Copyright (c) 2016 Ofek Lev
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

import requests
from core.meta import Unspent

DEFAULT_TIMEOUT = 50

def set_service_timeout(seconds):
    global DEFAULT_TIMEOUT
    DEFAULT_TIMEOUT = seconds

class ElectrumAPI:
    UNSPENT_API = 'https://api.mbc.wiki/?method=blockchain.address.allutxo&params[]={}'

    @classmethod
    def get_unspent(cls, address):
        r = requests.get(cls.UNSPENT_API.format(address), timeout=DEFAULT_TIMEOUT)

        if r.status_code == 500:
            return []
        elif r.status_code != 200:  # pragma: no cover
            raise ConnectionError

        if 'error' in r.json():
            raise Exception(r.json()['error']['message'])

        return [
            Unspent(tx['value'],
                    tx['script'],
                    tx['tx_hash'],
                    tx['tx_pos'])
            for tx in r.json()['result']
        ][::-1]

class NetworkAPI:
    IGNORED_ERRORS = (ConnectionError,
                      requests.exceptions.ConnectionError,
                      requests.exceptions.Timeout,
                      requests.exceptions.ReadTimeout)

    GET_UNSPENT_MAIN = [ElectrumAPI.get_unspent]

    @classmethod
    def get_unspent(cls, address):
        """Gets all unspent transaction outputs belonging to an address.

        :param address: The address in question.
        :type address: ``str``
        :raises ConnectionError: If all API services fail.
        :rtype: ``list`` of :class:`~core.meta.Unspent`
        """

        for api_call in cls.GET_UNSPENT_MAIN:
            try:
                return api_call(address)
            except cls.IGNORED_ERRORS:
                pass

        raise ConnectionError('All APIs are unreachable.')
