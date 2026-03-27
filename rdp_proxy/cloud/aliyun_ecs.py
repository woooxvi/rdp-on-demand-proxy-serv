from __future__ import annotations

import importlib

from rdp_proxy.config import CloudConfig
from rdp_proxy.cloud.base import CloudProvider


class AliyunECSProvider(CloudProvider):
    def __init__(self, cfg: CloudConfig):
        client_mod = importlib.import_module("aliyunsdkcore.client")
        self._cfg = cfg
        self._client = client_mod.AcsClient(cfg.secret_id, cfg.secret_key, cfg.region)

    def get_instance_state(self) -> str:
        req_mod = importlib.import_module("aliyunsdkecs.request.v20140526.DescribeInstancesRequest")
        req = req_mod.DescribeInstancesRequest()
        req.set_accept_format("json")
        req.set_InstanceIds([self._cfg.instance_id])

        resp_bytes = self._client.do_action_with_exception(req)
        import json

        resp = json.loads(resp_bytes)
        instances = resp.get("Instances", {}).get("Instance", [])
        if not instances:
            return "UNKNOWN"

        raw = str(instances[0].get("Status", "")).lower()
        if raw == "running":
            return "RUNNING"
        if raw == "stopped":
            return "STOPPED"
        if raw == "starting":
            return "STARTING"
        if raw == "stopping":
            return "STOPPING"
        if raw == "pending":
            return "PENDING"
        return "UNKNOWN"

    def start_instance(self) -> None:
        req_mod = importlib.import_module("aliyunsdkecs.request.v20140526.StartInstanceRequest")
        req = req_mod.StartInstanceRequest()
        req.set_accept_format("json")
        req.set_InstanceId(self._cfg.instance_id)
        self._client.do_action_with_exception(req)

    def stop_instance(self, stop_mode: str) -> None:
        req_mod = importlib.import_module("aliyunsdkecs.request.v20140526.StopInstanceRequest")
        req = req_mod.StopInstanceRequest()
        req.set_accept_format("json")
        req.set_InstanceId(self._cfg.instance_id)
        if stop_mode:
            req.set_StoppedMode(stop_mode)
        self._client.do_action_with_exception(req)
