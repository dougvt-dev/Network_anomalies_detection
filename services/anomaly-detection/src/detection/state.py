"""Trạng thái tồn tại qua nhiều cửa sổ: baseline EWMA, bảng IP↔MAC, các đích đã từng gặp.

Giai đoạn 1 lưu trong bộ nhớ (mất khi restart, baseline phải học lại).
Chuyển sang Redis: viết một class cùng interface StateStore và truyền vào DetectionEngine.
"""
from collections import OrderedDict, defaultdict
from typing import Any, Protocol


class StateStore(Protocol):
    def get(self, namespace: str, key: str, default: Any = None) -> Any: ...
    def set(self, namespace: str, key: str, value: Any) -> None: ...


class InMemoryStateStore:
    """Dict theo namespace, mỗi namespace giới hạn số key (bỏ key ít dùng nhất - LRU)."""

    def __init__(self, max_keys_per_namespace: int = 100_000):
        self.max_keys = max_keys_per_namespace
        self._data: dict[str, OrderedDict] = defaultdict(OrderedDict)

    def get(self, namespace: str, key: str, default: Any = None) -> Any:
        bucket = self._data[namespace]
        if key not in bucket:
            return default
        bucket.move_to_end(key)
        return bucket[key]

    def set(self, namespace: str, key: str, value: Any) -> None:
        bucket = self._data[namespace]
        bucket[key] = value
        bucket.move_to_end(key)
        if len(bucket) > self.max_keys:
            bucket.popitem(last=False)
