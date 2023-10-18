# Copyright (C) 2022 Alteryx, Inc. All rights reserved.
#
# Licensed under the ALTERYX SDK AND API LICENSE AGREEMENT;
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    https://www.alteryx.com/alteryx-sdk-and-api-license-agreement
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Example output tool."""
import base64
from datetime import datetime
import io
from time import sleep
from typing import Callable, Literal
from uuid import uuid4

from ayx_python_sdk.core import (
    Anchor,
    PluginV2,
)
from ayx_python_sdk.providers.amp_provider.amp_provider_v2 import AMPProviderV2

import jwt
import pyarrow.parquet as pq
import pyarrow as pa
import requests

DEFAULT_TIMEOUT = 5
DEFAULT_CHECK_OPERATION_DELAY = 0.5


class Toucan(PluginV2):
    """A sample Plugin that passes data from an input connection to an output connection."""

    def __init__(self, provider: AMPProviderV2):
        """Construct a plugin."""
        self.provider = provider
        self.provider.io.info("Toucan tool started")

    def on_record_batch(self, batch: "pa.Table", anchor: Anchor) -> None:
        """
        Process the passed record batch.

        The method that gets called whenever the plugin receives a record batch on an input.

        This method IS NOT called during update-only mode.

        Parameters
        ----------
        batch
            A pyarrow Table containing the received batch.
        anchor
            A namedtuple('Anchor', ['name', 'connection']) containing input connection identifiers.
        """
        upload_on_toucan_datahub(
            batch,
            baseroute=self.provider.tool_config["baseroute"],
            app_id=self.provider.tool_config["appId"],
            opaque_token=self.provider.tool_config["opaqueToken"],
            domain=self.provider.tool_config["datasetName"],
            log=self.provider.io.info,
        )

    def on_incoming_connection_complete(self, anchor: Anchor) -> None:
        """
        Call when an incoming connection is done sending data including
        when no data is sent on an optional input anchor.

        This method IS NOT called during update-only mode.

        Parameters
        ----------
        anchor
            NamedTuple containing anchor.name and anchor.connection.
        """
        self.provider.io.info(
            f"Received complete update from {anchor.name}:{anchor.connection}."
        )

    def on_complete(self) -> None:
        """
        Clean up any plugin resources, or push records for an input tool.

        This method gets called when all other plugin processing is complete.

        In this method, a Plugin designer should perform any cleanup for their plugin.
        However, if the plugin is an input-type tool (it has no incoming connections),
        processing (record generation) should occur here.

        Note: A tool with an optional input anchor and no incoming connections should
        also write any records to output anchors here.
        """
        self.provider.io.info("Toucan tool done.")


def forge_opaque_token(
    auth_service_base_url: str,
    tenant_id: str,
    workspace_id: str,
    client_id: str,
    client_secret: str,
    private_key: str,
    *,
    log: Callable[[str], None] = print,
) -> str:
    log("Generating token... started")
    token = {
        "iss": f"{tenant_id}-embed",
        "aud": f"{auth_service_base_url}/{tenant_id}/oauth/oauth-token",
        "exp": datetime.now().timestamp() + 86400,  # 1 day
        "jti": str(uuid4()),
        "sub": client_id,
        "embed_context": {
            "username": "toucalteryx",
            "workspace_id": workspace_id,
            "roles": ["ADMIN"],
        },
    }
    signed_token = jwt.encode(token, private_key, algorithm="RS512")

    creds = base64.b64encode(f"{client_id}:{client_secret}".encode("utf-8")).decode(
        "utf-8"
    )
    res = requests.post(
        f"{auth_service_base_url}/{tenant_id}/oauth/oauth-token",
        data={
            "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
            "scope": "embed",
            "assertion": signed_token,
        },
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "Authorization": f"Basic {creds}",
        },
        timeout=DEFAULT_TIMEOUT,
    )
    try:
        assert res.status_code == 200
    except AssertionError:
        log(f"Error: {res.json()}")

    opaque_token = res.json()["access_token"]
    log(f"Generating token... done (opaque token: {opaque_token})")
    return opaque_token


def get_operation_status(
    operation_id: str,
    *,
    baseroute: str,
    app_id: str,
    opaque_token: str,
    log: Callable[[str], None],
) -> Literal["pending", "running", "successful", "failed"]:
    res = requests.get(
        f"{baseroute}/{app_id}/operations/state/{operation_id}",
        headers={"authorization": f"Bearer {opaque_token}"},
        timeout=DEFAULT_TIMEOUT,
    )
    try:
        assert res.status_code == 200
    except AssertionError:
        log(f"Error: {res.json()}")
    return res.json()["status"]


# UPLOAD PYARROW TABLE
def upload_table_as_file(
    table: pa.Table,
    *,
    baseroute: str,
    app_id: str,
    opaque_token: str,
    domain: str,
    log: Callable[[str], None] = print,
) -> None:
    log(f"Uploading domain {domain!r}... started")
    buffer = io.BytesIO()
    pq.write_table(table, buffer)
    file_size = buffer.tell()
    buffer.seek(0)
    res = requests.post(
        f"{baseroute}/{app_id}/data/sources",
        headers={"authorization": f"Bearer {opaque_token}"},
        timeout=DEFAULT_TIMEOUT,
        data={
            "filename": f"{domain}.parquet",
            "dzchunkindex": 0,
            "dzchunkbyteoffset": 0,
            "dztotalchunkcount": 1,
            "dztotalfilesize": file_size,
        },
        files={
            "file": buffer,
        },
    )
    try:
        assert res.status_code == 200
    except AssertionError:
        log(f"Error: {res.json()}")
    operation_id = res.json()["operation_id"]

    log(f"Uploading domain {domain!r}... (operation_id: {operation_id})")
    while get_operation_status(
        operation_id,
        baseroute=baseroute,
        app_id=app_id,
        opaque_token=opaque_token,
        log=log,
    ) in {"pending", "running"}:
        sleep(DEFAULT_CHECK_OPERATION_DELAY)
        log(f"Uploading domain {domain!r}... (operation_id: {operation_id})")

    log(f"Uploading domain {domain!r}... done")


# REFRESH DOMAIN
def refresh_domain(
    *,
    baseroute: str,
    app_id: str,
    opaque_token: str,
    domain: str,
    log: Callable[[str], None] = print,
) -> None:
    log(f"Refreshing domain {domain!r}... started")
    res = requests.post(
        f"{baseroute}/{app_id}/operations?stage=staging",
        headers={"authorization": f"Bearer {opaque_token}"},
        timeout=DEFAULT_TIMEOUT,
        json={
            "operations": ["preprocess_data_sources"],
            "output_domains": [domain],
        },
    )
    try:
        assert res.status_code == 200
    except AssertionError:
        log(f"Error: {res.json()}")
    operation_id = res.json()["operation_id"]

    log(f"Refreshing domain {domain!r}... (operation_id: {operation_id})")
    while get_operation_status(
        operation_id,
        baseroute=baseroute,
        app_id=app_id,
        opaque_token=opaque_token,
        log=log,
    ) in {"pending", "running"}:
        sleep(DEFAULT_CHECK_OPERATION_DELAY)
        log(f"Refreshing domain {domain!r}... (operation_id: {operation_id})")

    log(f"Refreshing domain {domain!r}... done")


# CREATE QUERY
def create_query(
    *,
    baseroute: str,
    app_id: str,
    opaque_token: str,
    domain: str,
    log: Callable[[str], None] = print,
):
    log(f"Creating query for domain {domain!r}... started")
    res = requests.put(
        f"{baseroute}/{app_id}/queries",
        headers={"authorization": f"Bearer {opaque_token}"},
        timeout=DEFAULT_TIMEOUT,
        json=[
            {
                "type": "vqb_pipeline_over_connection",
                "materialized": True,
                "uid": f"domain__{domain}",
                "name": domain,
                "extra_domains": {
                    f"file - {domain}": {
                        "connection_uid": "__PEAKINA__",
                        "config": {
                            "uid": None,
                            "uri": f"{domain}.parquet",
                            "type": "parquet",
                            "match": None,
                            "expire": None,
                        },
                    }
                },
                "vqb_pipeline": [
                    {
                        "name": "domain",
                        "domain": f"file - {domain}",
                    }
                ],
            }
        ],
    )
    try:
        assert res.status_code == 200
    except AssertionError:
        log(f"Error: {res.json()}")
    log(f"Creating query for domain {domain!r}... done")


def upload_on_toucan_datahub(
    table: pa.Table,
    *,
    baseroute: str,
    app_id: str,
    opaque_token: str,
    domain: str,
    log: Callable[[str], None] = print,
) -> None:
    log("Uploading to Toucan...")
    upload_table_as_file(
        table,
        baseroute=baseroute,
        app_id=app_id,
        opaque_token=opaque_token,
        domain=domain,
        log=log,
    )
    create_query(
        baseroute=baseroute,
        app_id=app_id,
        opaque_token=opaque_token,
        domain=domain,
        log=log,
    )
    refresh_domain(
        baseroute=baseroute,
        app_id=app_id,
        opaque_token=opaque_token,
        domain=domain,
        log=log,
    )
