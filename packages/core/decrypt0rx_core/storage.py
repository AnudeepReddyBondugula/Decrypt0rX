"""Object storage for captured request/response bodies.

Bodies dwarf the metadata, so they live in S3/MinIO (or a mounted volume for
single-node installs) and the flow row keeps only a reference.
"""

from __future__ import annotations

import asyncio
import logging
import os
from pathlib import Path
from typing import Protocol

logger = logging.getLogger(__name__)


class BodyStore(Protocol):
    async def put(self, key: str, data: bytes, content_type: str | None = None) -> str: ...
    async def get(self, key: str) -> bytes: ...
    async def delete(self, key: str) -> None: ...
    async def close(self) -> None: ...


class LocalBodyStore:
    """Filesystem-backed store; fine for one node, not for replicas."""

    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    def _path(self, key: str) -> Path:
        safe = key.replace("..", "_").lstrip("/")
        path = self.root / safe
        path.parent.mkdir(parents=True, exist_ok=True)
        return path

    async def put(self, key: str, data: bytes, content_type: str | None = None) -> str:
        await asyncio.to_thread(self._path(key).write_bytes, data)
        return key

    async def get(self, key: str) -> bytes:
        return await asyncio.to_thread(self._path(key).read_bytes)

    async def delete(self, key: str) -> None:
        path = self._path(key)
        await asyncio.to_thread(lambda: path.unlink(missing_ok=True))

    async def close(self) -> None:
        return None


class S3BodyStore:
    """boto3 in a worker thread - the sync client is battle-tested and the
    capture path already buffers, so the extra thread hop is not on the hot
    byte-forwarding loop."""

    def __init__(
        self,
        bucket: str,
        endpoint_url: str | None,
        access_key: str,
        secret_key: str,
        region: str = "us-east-1",
    ) -> None:
        import boto3
        from botocore.config import Config

        self.bucket = bucket
        self._client = boto3.client(
            "s3",
            endpoint_url=endpoint_url or None,
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            region_name=region,
            config=Config(
                signature_version="s3v4",
                retries={"max_attempts": 3, "mode": "standard"},
                connect_timeout=3,
                read_timeout=10,
            ),
        )

    def ensure_bucket(self) -> None:
        from botocore.exceptions import ClientError

        try:
            self._client.head_bucket(Bucket=self.bucket)
        except ClientError:
            try:
                self._client.create_bucket(Bucket=self.bucket)
                logger.info("created body bucket %s", self.bucket)
            except ClientError:
                logger.warning("could not create bucket %s", self.bucket, exc_info=True)

    async def put(self, key: str, data: bytes, content_type: str | None = None) -> str:
        kwargs = {"Bucket": self.bucket, "Key": key, "Body": data}
        if content_type:
            kwargs["ContentType"] = content_type[:200]
        await asyncio.to_thread(lambda: self._client.put_object(**kwargs))
        return key

    async def get(self, key: str) -> bytes:
        def _read() -> bytes:
            obj = self._client.get_object(Bucket=self.bucket, Key=key)
            return obj["Body"].read()

        return await asyncio.to_thread(_read)

    async def delete(self, key: str) -> None:
        await asyncio.to_thread(
            lambda: self._client.delete_object(Bucket=self.bucket, Key=key)
        )

    async def close(self) -> None:
        await asyncio.to_thread(self._client.close)


def build_body_store(settings) -> BodyStore:
    if settings.storage_backend == "local":
        return LocalBodyStore(settings.local_storage_path)
    store = S3BodyStore(
        bucket=settings.s3_bucket,
        endpoint_url=settings.s3_endpoint_url,
        access_key=settings.s3_access_key,
        secret_key=settings.s3_secret_key,
        region=settings.s3_region,
    )
    if os.getenv("DECRYPT0RX_S3_ENSURE_BUCKET", "1") == "1":
        store.ensure_bucket()
    return store


def body_key(flow_id, direction: str) -> str:
    """Date-partitioned key so lifecycle rules can expire old captures."""
    from datetime import datetime, timezone

    day = datetime.now(timezone.utc).strftime("%Y/%m/%d")
    return f"{day}/{flow_id}/{direction}.bin"
