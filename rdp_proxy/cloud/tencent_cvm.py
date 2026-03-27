from __future__ import annotations

import importlib

from rdp_proxy.config import CloudConfig
from rdp_proxy.cloud.base import CloudProvider


class TencentCVMProvider(CloudProvider):
    def __init__(self, cfg: CloudConfig):
        credential = importlib.import_module("tencentcloud.common.credential")
        cvm_client = importlib.import_module("tencentcloud.cvm.v20170312.cvm_client")

        self._cfg = cfg
        cred = credential.Credential(cfg.secret_id, cfg.secret_key)
        self._client = cvm_client.CvmClient(cred, cfg.region)

    def get_instance_state(self) -> str:
        exc_mod = importlib.import_module("tencentcloud.common.exception.tencent_cloud_sdk_exception")
        models = importlib.import_module("tencentcloud.cvm.v20170312.models")
        TencentCloudSDKException = exc_mod.TencentCloudSDKException

        req = models.DescribeInstancesRequest()
        req.InstanceIds = [self._cfg.instance_id]

        try:
            resp = self._client.DescribeInstances(req)
        except TencentCloudSDKException:
            return "UNKNOWN"

        if not resp.InstanceSet:
            return "UNKNOWN"

        raw_state = (resp.InstanceSet[0].InstanceState or "").upper()
        if raw_state == "RUNNING":
            return "RUNNING"
        if raw_state == "STOPPED":
            return "STOPPED"
        if raw_state == "STARTING":
            return "STARTING"
        if raw_state == "STOPPING":
            return "STOPPING"
        return "UNKNOWN"

    def start_instance(self) -> None:
        models = importlib.import_module("tencentcloud.cvm.v20170312.models")

        req = models.StartInstancesRequest()
        req.InstanceIds = [self._cfg.instance_id]
        self._client.StartInstances(req)

    def stop_instance(self, stop_mode: str) -> None:
        models = importlib.import_module("tencentcloud.cvm.v20170312.models")

        req = models.StopInstancesRequest()
        req.InstanceIds = [self._cfg.instance_id]
        req.StoppedMode = stop_mode
        req.StopType = "SOFT_FIRST"
        self._client.StopInstances(req)
