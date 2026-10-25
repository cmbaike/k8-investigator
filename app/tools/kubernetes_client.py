from functools import lru_cache

from kubernetes import client, config
from kubernetes.config.config_exception import ConfigException


class KubernetesConfigurationError(RuntimeError):
    pass


@lru_cache(maxsize=1)
def load_kubernetes_config() -> None:
    try:
        config.load_incluster_config()
        return
    except ConfigException:
        pass

    try:
        config.load_kube_config()
    except ConfigException as exc:
        raise KubernetesConfigurationError(
            "No usable Kubernetes configuration was found."
        ) from exc


def core_v1() -> client.CoreV1Api:
    load_kubernetes_config()
    return client.CoreV1Api()


def apps_v1() -> client.AppsV1Api:
    load_kubernetes_config()
    return client.AppsV1Api()
