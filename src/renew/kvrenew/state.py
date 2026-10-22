"""Small state store with optimistic concurrency (ETag), used for the per-certificate lease and the order record.

Azure Table Storage is used in Azure; an in-memory store is used by the unit tests.
`get` returns (data, etag); `put` raises StateConflict when the etag is stale, which is what makes the lease safe.
"""
from __future__ import annotations

import copy
import json
from typing import Optional


class StateConflict(Exception):
    """The record changed (or was created) since it was read."""


class MemoryStore:
    def __init__(self) -> None:
        self._d: dict = {}
        self._n = 0

    def get(self, key: str):
        rec = self._d.get(key)
        return (copy.deepcopy(rec[0]), rec[1]) if rec else (None, None)

    def put(self, key: str, data: dict, etag: Optional[str]) -> str:
        cur = self._d.get(key)
        if (cur is None and etag is not None) or (cur is not None and etag != cur[1]):
            raise StateConflict(key)
        self._n += 1
        self._d[key] = (copy.deepcopy(data), str(self._n))
        return str(self._n)


class TableStore:
    PARTITION = "cert"

    def __init__(self, endpoint: str, table: str, credential) -> None:
        from azure.data.tables import TableClient

        self._t = TableClient(endpoint=endpoint, table_name=table, credential=credential)

    def get(self, key: str):
        from azure.core.exceptions import ResourceNotFoundError

        try:
            e = self._t.get_entity(self.PARTITION, key)
        except ResourceNotFoundError:
            return None, None
        return json.loads(e["json"]), e.metadata["etag"]

    def put(self, key: str, data: dict, etag: Optional[str]) -> str:
        from azure.core import MatchConditions
        from azure.core.exceptions import ResourceExistsError, ResourceModifiedError
        from azure.data.tables import UpdateMode

        ent = {"PartitionKey": self.PARTITION, "RowKey": key, "json": json.dumps(data)}
        try:
            if etag is None:
                res = self._t.create_entity(ent)
            else:
                res = self._t.update_entity(ent, mode=UpdateMode.REPLACE, etag=etag, match_condition=MatchConditions.IfNotModified)
        except (ResourceExistsError, ResourceModifiedError) as e:
            raise StateConflict(key) from e
        return res["etag"]
