#!/usr/bin/env python3.8
#
# param retry started runtime logger memo resource patch body reason diff old new spec meta status uid name namespace labels annotations
#

import json
import logging
import os
import random
import signal
import string
import sys
import time
from queue import Queue
from threading import Event, Thread

import kubernetes as kube

# from openshift.dynamic import DynamicClient
PID = os.getpid()
logging.basicConfig(
    #format=f'time="%(asctime)s" pid=%(process)d file=%(funcName)s:%(lineno)d level=%(levelname)s message="%(message)s"',
    format=f'time="%(asctime)s" level=%(levelname)s message="%(message)s"',
    level=logging.INFO,
)

INFO = logging.info
DEBUG = logging.debug
ERROR = logging.error


def JSON(d):
    try:
        return json.dumps(dict(d), indent=3)
    except:
        return str(d)


GROUP_ROUTE, GROUP_ROUTE_VERSION, GROUP_ROUTE_PLURAL = (
    "route.openshift.io",
    "v1",
    "routes",
)
GROUP_CONFIG, GROUP_CONFIG_VERSION, GROUP_CONFIG_PLURAL = (
    "config.openshift.io",
    "v1",
    "ingresses",
)

VALID_TLS_TERMINATIONS = ("edge", "reencrypt")

NAMESPACE = os.environ.get('NAMESPACE')
DRY_RUN = (os.environ.get('DRY_RUN', 'false') == 'true')
if DRY_RUN:
    INFO('DRY_RUN is active')

ANNOTATION_TLS_PREFIX = "tls.getup.io"
# Ignore Routes with this annotation.
ANNOTATION_TLS_ROUTE_IGNORE = f"{ANNOTATION_TLS_PREFIX}/ignore"
# Name of the Secret for the tls certificate. Auto-generated if not set.
ANNOTATION_TLS_INGRESS_SECRET_NAME = f"{ANNOTATION_TLS_PREFIX}/secret-name"
# Name of the Route used to create this Ingress.
ANNOTATION_TLS_SOURCE_ROUTE = f"{ANNOTATION_TLS_PREFIX}/source-route"
# Prefix used by short hostname.
ANNOTATION_TLS_INGRESS_ID = f"{ANNOTATION_TLS_PREFIX}/ingress-id"

# Certmanager annotations
ANNOTATIONS_CERTMANAGER = "cert-manager.io"
ANNOTATIONS_CERTMANAGER_HTTP01_SOLVER = f"acme.{ANNOTATIONS_CERTMANAGER}/http01-solver"
ANNOTATION_CERT_MANAGER_CLUSTER_ISSUER = f"{ANNOTATIONS_CERTMANAGER}/cluster-issuer"

# Cert Utils Operator namespace - https://github.com/redhat-cop/cert-utils-operator
ANNOTATIONS_CERT_UTILS_OPERATOR = "cert-utils-operator.redhat-cop.io"
# Cert Utils Operator source secret annotation
ANNOTATIONS_CERT_UTILS_OPERATOR_CERTS_FROM_SECRET = f"{ANNOTATIONS_CERT_UTILS_OPERATOR}/certs-from-secret"

# Cluster apps domain. Defaults to discovered from object below.
ENV_CLUSTER_DOMAIN = os.environ.get("CLUSTER_DOMAIN")
# Name of ingresses.config.openshift.io to look for ingress domain suffix
ENV_INGRESS_CONFIG_NAME = os.environ.get("INGRESS_CONFIG_NAME", "cluster")
# Default ClusterIssuer name to set into created Ingress
ENV_CLUSTER_ISSUER = os.environ.get("CLUSTER_ISSUER", "letsencrypt-staging-http01")
# Default Ingress Class name to set into created Ingress
# Do not set this to 'openshift-default' in order to avoid an infinite loop
# creating ingress->route->ingress->route...
ENV_INGRESS_CLASS_NAME = os.environ.get("INGRESS_CLASS_NAME", "route-to-ingress")
ENV_IGNORE_DANGEROUS_INGRESS_CLASS_NAME = os.environ.get("IGNORE_DANGEROUS_INGRESS_CLASS_NAME", "false")

if (ENV_INGRESS_CLASS_NAME == "openshift-default" and ENV_IGNORE_DANGEROUS_INGRESS_CLASS_NAME != "true"):
    ERROR("Setting INGRESS_CLASS_NAME=openshift-default may lead to infinite creation of ingresses/routes by openshift router controller.")
    ERROR("Please also set IGNORE_DANGEROUS_INGRESS_CLASS_NAME=true if you known what you are doing.")
    sys.exit(1)


############################################
## Common utils

class Cache:
    INGRESS_CACHE = {}

    def _key(self, meta):
        return (meta['namespace'], meta['name'])

    def set(self, obj):
        key = self._key(obj['metadata'])
        DEBUG(f"Add cache: {key}")
        self.INGRESS_CACHE[key] = obj
        return obj

    def get(self, meta):
        key = self._key(meta)
        obj = self.INGRESS_CACHE.get(key, None)

        if obj:
            DEBUG(f"Hit cache: {key}")
        else:
            DEBUG(f"Miss cache: {key}")

        return obj

    def delete(self, meta):
        key = self._key(meta)
        DEBUG(f"Delete cache: {key}")
        self.INGRESS_CACHE.pop(key, None)


CACHE = Cache()

def discover_ingress_domain(api_client):
    api = kube.client.CustomObjectsApi(api_client)
    try:
        config = api.get_cluster_custom_object(
            GROUP_CONFIG,
            GROUP_CONFIG_VERSION,
            GROUP_CONFIG_PLURAL,
            ENV_INGRESS_CONFIG_NAME,
        )
        return config["spec"]["domain"]
    except (KeyError, kube.client.exceptions.ApiException) as ex:
        ERROR(f"Failed to query for cluster domain ({GROUP_CONFIG_VERSION}.{GROUP_CONFIG}/{ENV_INGRESS_CONFIG_NAME}): {ex.status} {ex.reason}")
        ERROR("Please set INGRESS_CONFIG_NAME or CLUSTER_DOMAIN")
        sys.exit(1)


############################################
## Route utils


def ignore_route(route):
    meta, spec = route['metadata'], route['spec']
    anns = meta.get("annotations", {})

    if anns.get(ANNOTATION_TLS_ROUTE_IGNORE, None) is not None:
        INFO(f"Ignoring route with annotation {ANNOTATION_TLS_ROUTE_IGNORE}")
        return True

    if anns.get(ANNOTATIONS_CERTMANAGER_HTTP01_SOLVER):
        INFO(f"Ignoring cert-manager solver Ingress")
        return True

    ownerRefs = meta.get("ownerReferences")
    if ownerRefs:
        for ownerRef in ownerRefs:
            INFO(f'Ignoring owned route by {ownerRef["kind"]}/{ownerRef["name"]} ({ownerRef["uid"]})')
        return True

    tls_termination = spec.get("tls", {}).get("termination", "")
    if tls_termination.lower() not in VALID_TLS_TERMINATIONS:
        INFO(f'Ignoring Route with tls.termination="{tls_termination}". Requires one of: {", ".join(VALID_TLS_TERMINATIONS)}')
        return True

    port = spec.get('port', {})
    if 'targetPort' not in port:
        INFO(f'Ignoring Route without tls.port.targetPort')
        return True

    return False



def patch_route(route):
    meta, spec = route['metadata'], route['spec']
    namespace, name = meta["namespace"], meta["name"]
    api = kube.client.CustomObjectsApi()

    # TODO: remove unnecessary fields prior patching
    try:
        if DRY_RUN:
            INFO('DRY_RUN: api.patch_namespaced_custom_object('
                f'{GROUP_ROUTE}, '
                f'{GROUP_ROUTE_VERSION}, '
                f'{namespace}, '
                f'{GROUP_ROUTE_PLURAL}, '
                f'{name}, '
                'body=route)')
        else:
            api.patch_namespaced_custom_object(
                GROUP_ROUTE,
                GROUP_ROUTE_VERSION,
                namespace,
                GROUP_ROUTE_PLURAL,
                name,
                body=route)
    except kube.client.exceptions.ApiException as ex:
        ERROR(f"Failed api call: patch_namespaced_custom_object({GROUP_ROUTE}, {GROUP_ROUTE_VERSION}, namespace={namespace}, {GROUP_ROUTE_PLURAL}, name={name}, body=route): {ex.status} {ex.reason} {ex.body}")
        DEBUG(JSON(route))


def ensure_route(route, ingress):
    changed = False
    if not route['metadata'].get('annotations', {}).get(ANNOTATIONS_CERT_UTILS_OPERATOR_CERTS_FROM_SECRET):
        if 'annotations' not in route['metadata']:
            route['metadata']['annotations'] = {}
        route['metadata']['annotations'][ANNOTATION_CERT_MANAGER_CLUSTER_ISSUER] = ingress["spec"]["tls"][0]["secretName"]
        changed = True

    if changed:
        patch_route(route)


############################################
# Route Handlers


def handle_route_create(meta, spec, route):
    ingress = CACHE.get(meta)

    if not ingress:
        ingress = create_ingress(route)
    else:
        ensure_ingress(ingress)

    ensure_route(route, ingress)


def handle_route_update(meta, spec, route):
    ingress = CACHE.get(meta)

    if not ingress:
        ingress = create_ingress(route)
    else:
        ensure_ingress(ingress)

    ensure_route(route, ingress)


def handle_route_delete(meta, spec, route):
    ingress = CACHE.get(meta)

    if ingress:
        delete_ingress(ingress)


############################################
## Ingress utils

def ignore_ingress(ingress):
    if get_ingress_id(ingress) == None:
        INFO(f"Ignoring Ingress without ingress-id annotation")
        return True

    return False

def make_ingress_id():
    return (random.choice(string.ascii_lowercase)
            + "".join([random.choice(string.digits + string.ascii_lowercase) for i in range(5)]))


def get_ingress_id(ingress):
    return (
        ingress.get("metadata", {})
        .get("annotations", {})
        .get(ANNOTATION_TLS_INGRESS_ID, None)
    )


def make_ingress(route):
    meta, spec = route['metadata'], route['spec']
    namespace, name = meta["namespace"], meta["name"]

    try:
        service_port = {"number": int(spec["port"]["targetPort"])}
    except ValueError:
        service_port = {"name": spec["port"]["targetPort"]}

    api_version = route["apiVersion"]
    host = spec.get("host")
    path = spec.get("path", "/")
    service_name = spec["to"]["name"]
    ingress_id = make_ingress_id()

    INFO(f"make_ingress(api_version={api_version}, host={host}, path={path}, service_name={service_name}, service_port={service_port}, has_tls={has_tls}, ingress_id={ingress_id})")

    anns = {
        ANNOTATION_CERT_MANAGER_CLUSTER_ISSUER: ENV_CLUSTER_ISSUER,
        ANNOTATION_TLS_SOURCE_ROUTE: name,
        ANNOTATION_TLS_INGRESS_ID: ingress_id,
    }
    for k, v in meta.get("annotations", {}).items():
        if not k.startswith("kopf.zalando.org"):
            anns[k] = v
        else:
            INFO(f"Discarding annotation: {k}")

    secret_name = anns.get(ANNOTATION_TLS_INGRESS_SECRET_NAME, f'{name}-ingress-tls')
    ingress_class_name = anns.pop("kubernetes.io/ingress.class", ENV_INGRESS_CLASS_NAME)

    return {
        "metadata": {
            "name": name,
            "namespace": namespace,
            "annotations": anns,
            "labels": meta.get("labels", {}),
            "ownerReferences": [
                {
                    "apiVersion": api_version,
                    "controller": True,
                    "kind": "Route",
                    "name": name,
                    "uid": meta["uid"],
                }
            ],
        },
        "spec": {
            "ingressClassName": ingress_class_name,
            "rules": [
                {
                    "host": host,
                    "http": {
                        "paths": [
                            {
                                "backend": {
                                    "service": {
                                        "name": service_name,
                                        "port": service_port,
                                    }
                                },
                                "path": path,
                                "pathType": "Prefix",  ## https://github.com/okd-project/okd/discussions/1309
                            }
                        ]
                    },
                }
            ],
            "tls": [
                {
                    "hosts": [f"{ingress_id}.{ENV_CLUSTER_DOMAIN}", host],
                    "secretName": secret_name,
                }
            ]
        }
    }


def create_ingress(route):
    meta, spec = route['metadata'], route['spec']
    namespace, name = meta["namespace"], meta["name"]

    INFO(f"New Ingress ID: {ingress_id}")
    ingress = make_ingress(route)

    if not ingress:
        # not enough data to create an Ingress
        return

    INFO(f'Creating ingress: {namespace}/{name}')
    DEBUG(JSON(ingress))

    api = kube.client.NetworkingV1Api()
    try:
        if DRY_RUN:
            INFO(f'DRY_RUN: api.create_namespaced_ingress(namespace={namespace}, name={name}, body=ingress)')
        else:
            api.create_namespaced_ingress(namespace=namespace, body=ingress)
    except kube.client.exceptions.ApiException as ex:
        ERROR(f'Failed api call: create_namespaced_ingress(namespace={amespace}, name={name}, body={ingress}): {ex.status} {ex.reason}')

    return ingress


def patch_ingress(namespace, name, ingress):
    api = kube.client.NetworkingV1Api()
    # TODO: remove unnecessary fields prior patching
    try:
        if DRY_RUN:
            INFO('DRY_RUN: api.patch_namespaced_ingress('
                f'namespace={namespace}, '
                f'name={name}, '
                'body=ingress)')
        else:
            api.patch_namespaced_ingress(
                namespace=namespace,
                name=name,
                body=ingress)
    except kube.client.exceptions.ApiException as ex:
        ERROR(f'Failed api call: patch_namespaced_ingress(namespace={namespace}, name={name}, body=<below>): {ex.status} {ex.reason} {ex.body}')
        DEBUG(JSON(ingress))


def ensure_ingress(ingress):
    meta, spec = ingress['metadata'], ingress['spec']
    changed = False

    if ingress['metadata'].get('annotations', {}).get(ANNOTATION_CERT_MANAGER_CLUSTER_ISSUER) != ENV_CLUSTER_ISSUER:
        if 'annotations' not in ingress['metadata']:
            ingress['metadata']['annotations'] = {}
        ingress['metadata']['annotations'][ANNOTATION_CERT_MANAGER_CLUSTER_ISSUER] = ENV_CLUSTER_ISSUER
        changed = True

    if changed:
        patch_ingress(ingress['metadata']['namespace'], ingress['metadata']['name'], ingress)


def delete_ingress(ingress):
    meta, spec = ingress['metadata'], ingress['spec']
    namespace, name = meta["namespace"], meta["name"]
    api = kube.client.NetworkingV1Api()

    INFO(f'Deleting ingress: {namespace}/{name}')
    try:
        if DRY_RUN:
            INFO(f'DRY_RUN: api.delete_namespaced_ingress(namespace={namespace}, name={name})')
        else:
            api.delete_namespaced_ingress(namespace=namespace, name=name)
    except kube.client.exceptions.ApiException as ex:
        ERROR(f"Failed api call: delete_namespaced_ingress(namespace={namespace}, name={name}): {ex.status} {ex.reason}")


############################################
# Ingress Handlers


def handle_ingress_create(meta, spec, ingress):
    CACHE.set(ingress)
    ensure_ingress(ingress)


def handle_ingress_update(meta, spec, ingress):
    CACHE.set(ingress)

    ensure_ingress(meta, spec, ingress)


def handle_ingress_delete(meta, spec, ingress):
    CACHE.delete(meta)


########################################################################33


# TODO: unify both informers
class RouteInformer(Thread):
    def __init__(self, api_client, queue, namespace, stop_event):
        Thread.__init__(self, name="RouteInformer")
        self.api_instance = kube.client.CustomObjectsApi(api_client)
        self.queue = queue
        self.namespace = namespace
        self.stop_event = stop_event

    def run(self):
        INFO(f"Starting {self.name} thread")
        resource_version = ""
        while True:
            while not self.stop_event.is_set():
                DEBUG("watch route")
                try:
                    self.watcher = kube.watch.Watch()
                    if self.namespace:
                        self.stream = self.watcher.stream(
                            self.api_instance.list_namespaced_custom_object,
                            GROUP_ROUTE,
                            GROUP_ROUTE_VERSION,
                            self.namespace,
                            GROUP_ROUTE_PLURAL,
                            resource_version=resource_version,
                            timeout_seconds=0)
                    else:
                        self.stream = self.watcher.stream(
                            self.api_instance.list_cluster_custom_object,
                            GROUP_ROUTE,
                            GROUP_ROUTE_VERSION,
                            GROUP_ROUTE_PLURAL,
                            resource_version=resource_version,
                            timeout_seconds=0)
                    for event in self.stream:
                        DEBUG(JSON(event))
                        self.queue.put(event)
                except Exception as ex:
                    INFO(f"Reconnecting {self.name}: {ex}")


class IngressInformer(Thread):
    def __init__(self, api_client, queue, namespace, stop_event):
        Thread.__init__(self, name="IngressInformer")
        self.api_instance = kube.client.NetworkingV1Api(api_client)
        self.queue = queue
        self.namespace = namespace
        self.stop_event = stop_event

    def run(self):
        INFO(f"Starting {self.name} thread")
        resource_version = ""
        while True:
            while not self.stop_event.is_set():
                DEBUG("watch ingress")
                try:
                    self.watcher = kube.watch.Watch()
                    if self.namespace:
                        self.stream = self.watcher.stream(
                            self.api_instance.list_namespaced_ingress,
                            self.namespace,
                            resource_version=resource_version,
                            timeout_seconds=0)
                    else:
                        self.stream = self.watcher.stream(
                            self.api_instance.list_ingress_for_all_namespaces,
                            resource_version=resource_version,
                            timeout_seconds=0)
                    for event in self.stream:
                        DEBUG(JSON(event))
                        self.queue.put(event)
                except Exception as ex:
                    INFO(f"Reconnecting {self.name}: {ex}")


########################################################################33
## Main

exit_count = 3

def sig_handler(signum, frame):
    if exit_count > 1:
        INFO(f"Signal handler called with signal {signum}")
        queue.put("exit")
        signal.setitimer(signal.ITIMER_REAL, 30)
        exit_count = exit_count - 1
    else:
        INFO(f"Signal handler called with signal {signum}. Forced exit...")
        sys.exit(2)


def force_exit(signum, frame):
    INFO(f"Forcing exit. Took too long to stop threads.")
    sys.exit(2)


if __name__ == "__main__":
    signal.signal(signal.SIGINT, sig_handler)
    signal.signal(signal.SIGTERM, sig_handler)
    signal.signal(signal.SIGALRM, force_exit)

    if "KUBERNETES_PORT" in os.environ:
        INFO("Using in-cluster config")
        kube.config.load_incluster_config()
    else:
        INFO(f'Using KUBECONFIG={os.environ.get("KUBECONFIG", "")}')
        kube.config.load_kube_config()

    api_client = kube.client.api_client.ApiClient()

    if not ENV_CLUSTER_DOMAIN:
        ENV_CLUSTER_DOMAIN = discover_ingress_domain(api_client)
        INFO(f"Found Ingress domain: {ENV_INGRESS_CLASS_NAME}")

    queue = Queue()
    stop_event = Event()

    ingress_informer = IngressInformer(api_client, queue, NAMESPACE, stop_event)
    ingress_informer.daemon = True
    ingress_informer.start()

    # give some time for Ingress to fill cache
    time.sleep(2)

    route_informer = RouteInformer(api_client, queue, NAMESPACE, stop_event)
    route_informer.daemon = True
    route_informer.start()

    while True:
        event = queue.get()

        if event == "exit":
            INFO("Exiting...")
            stop_event.set()
            # route_informer.stream.send('exit')
            # ingress_informer.stream.send('exit')
            # route_informer.watcher.stop()
            # ingress_informer.watcher.stop()
            api_client.close()
            route_informer.join(timeout=2)
            ingress_informer.join(timeout=2)
            sys.exit(0)

        oper = event['type']
        body = event['raw_object']
        kind = body['kind']
        meta = body['metadata']
        spec = body['spec']

        if not spec:
            continue

        INFO(f'{oper} {body["kind"]} {meta["namespace"]}/{meta["name"]}')

        if kind == "Ingress":
            if ignore_ingress(body):
                continue

            if oper == "ADDED":
                handle_ingress_create(meta, spec, body)
            elif oper == "MODIFIED":
                handle_ingress_update(meta, spec, body)
            elif oper == "DELETED":
                handle_ingress_delete(meta, spec, body)

        elif kind == "Route":
            if ignore_route(body):
                continue

            if oper == "ADDED":
                handle_route_create(meta, spec, body)
            elif oper == "MODIFIED":
                handle_route_update(meta, spec, body)
            elif oper == "DELETED":
                handle_route_delete(meta, spec, body)
