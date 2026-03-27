from __future__ import annotations

from rdp_proxy.cloud.base import CloudProvider
from rdp_proxy.cloud.aliyun_ecs import AliyunECSProvider
from rdp_proxy.cloud.tencent_cvm import TencentCVMProvider
from rdp_proxy.config import CloudConfig


def create_provider(cfg: CloudConfig) -> CloudProvider:
    if cfg.provider == "tencent_cvm":
        return TencentCVMProvider(cfg)
    if cfg.provider == "aliyun_ecs":
        return AliyunECSProvider(cfg)
    raise ValueError(f"Unsupported cloud provider: {cfg.provider}")
