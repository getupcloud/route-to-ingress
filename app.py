#!/usr/bin/env python3.8
#
# param retry started runtime logger memo resource patch body reason diff old new spec meta status uid name namespace labels annotations
#

import argparse
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


INFO = logging.info
DEBUG = logging.debug
ERROR = logging.error

DEFAULT_NAMESPACES = [ n.strip() for n in os.environ.get('NAMESPACES', '').split(',') ]
DEFAULT_IGNORED_NAMESPACES = [ n.strip() for n in os.environ.get('IGNORED_NAMESPACES', ','.join([
    'openshift-adp',
    'openshift-authentication',
    'openshift-console',
    'openshift-image-registry',
    'openshift-ingress-canary'
])).split(',') ]
DEFAULT_CLUSTER_DOMAIN = os.environ.get("CLUSTER_DOMAIN", "")
DEFAULT_ALLOWED_DOMAINS = os.environ.get("ALLOWED_DOMAINS", "")
DEFAULT_INGRESS_CONFIG_NAME = os.environ.get("INGRESS_CONFIG_NAME", "cluster")
DEFAULT_CLUSTER_ISSUER = os.environ.get("CLUSTER_ISSUER", "letsencrypt-staging-http01")
DEFAULT_INGRESS_CLASS_NAME = os.environ.get("INGRESS_CLASS_NAME", "route-to-ingress")
DEFAULT_IGNORE_DANGEROUS_INGRESS_CLASS_NAME = os.environ.get("IGNORE_DANGEROUS_INGRESS_CLASS_NAME", "false")


GROUP_ROUTE, GROUP_ROUTE_VERSION, GROUP_ROUTE_PLURAL = (
    "route.openshift.io",
    "v1",
    "routes",
)

GROUP_CONFIG, GROUP_CONFIG_VERSION = (
    "config.openshift.io",
    "v1"
)
GROUP_CONFIG_INGRESS_PLURAL = "ingresses"

VALID_TLS_TERMINATIONS = ("edge", "reencrypt")

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

args = None
parser = argparse.ArgumentParser(description='Controller to create Ingress objects from Route objects.', add_help=True)

parser.add_argument('-v', '--verbose',
    help='Turn on verbose logs.',
    action=argparse.BooleanOptionalAction,
    default=False)

parser.add_argument('--dry-run',
    help='Look into namespace only. May be used multiple times.',
    action=argparse.BooleanOptionalAction,
    default=False)

parser.add_argument('-n', '--namespaces',
    help='Look into specified namespaces only.',
    type=str,
    nargs='*',
    action="extend")

parser.add_argument('-i', '--ignored-namespaces',
    help=f'Look into specified namespaces only. (default: {", ".join(DEFAULT_IGNORED_NAMESPACES)})',
    type=str,
    nargs='*',
    action="extend",
    default=DEFAULT_IGNORED_NAMESPACES)

parser.add_argument('--cluster-domain',
    help='Set cluster domain. Auto-dicovered if not specified.',
    type=str,
    nargs=1)

parser.add_argument('--allowed-domains',
    help='What domains will be processed from Routes. Any other will be ignored. Defaults to value from --cluster-domain or auto-dicovery.',
    type=str,
    nargs='*')

parser.add_argument('--ingress-config-name',
    help=f'Object name for {GROUP_CONFIG}.{GROUP_CONFIG_INGRESS_PLURAL} for cluster-domain auto-dicover.',
    type=str,
    default=DEFAULT_INGRESS_CONFIG_NAME)

parser.add_argument('--cluster-issuer',
    help='ClusterIssuer name to add into newly created Ingresses.',
    type=str,
    default=DEFAULT_CLUSTER_ISSUER)

parser.add_argument('--ingress-class-name',
    help='Ingress Class Name to set into into newly created Ingresses. Note it can\'t conflict with existing ingress class names.',
    type=str,
    default=DEFAULT_INGRESS_CLASS_NAME)

parser.add_argument('--ignore-conflicting-ingress-class-name',
    help='Only to make sure you undestand you can\'t set an already used ingress class name.',
    action=argparse.BooleanOptionalAction,
    default=False)


############################################
## Common utils


def JSON(d):
    try:
        return json.dumps(dict(d), indent=3)
    except:
        return str(d)


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
            GROUP_CONFIG_INGRESS_PLURAL,
            args.ingress_config_name,
        )
        return config["spec"]["domain"]
    except (KeyError, kube.client.exceptions.ApiException) as ex:
        ERROR(f"Failed to query for cluster domain ({GROUP_CONFIG_VERSION}.{GROUP_CONFIG}/{args.ingress_config_name}): {ex.status} {ex.reason}")
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
        if args.dry_run:
            INFO('DRY_RUN: api.patch_namespaced_custom_object('
                f'{GROUP_ROUTE}, '
                f'{GROUP_ROUTE_VERSION}, '
                f'{namespace}, '
                f'{GROUP_ROUTE_PLURAL}, '
                f'{name}, '
                f'body={route})')
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
        route['metadata']['annotations'][ANNOTATIONS_CERT_UTILS_OPERATOR_CERTS_FROM_SECRET] = ingress["spec"]["tls"][0]["secretName"]
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

    INFO(f"make_ingress(api_version={api_version}, host={host}, path={path}, service_name={service_name}, service_port={service_port}, ingress_id={ingress_id})")

    anns = {
        ANNOTATION_CERT_MANAGER_CLUSTER_ISSUER: args.cluster_issuer,
        ANNOTATION_TLS_SOURCE_ROUTE: name,
        ANNOTATION_TLS_INGRESS_ID: ingress_id,
    }
    for k, v in meta.get("annotations", {}).items():
        if not k.startswith("kopf.zalando.org"):
            anns[k] = v
        else:
            INFO(f"Discarding annotation: {k}")

    secret_name = anns.get(ANNOTATION_TLS_INGRESS_SECRET_NAME, f'{name}-ingress-tls')
    ingress_class_name = anns.pop("kubernetes.io/ingress.class", args.ingress_class_name)

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
                    "hosts": [f"{ingress_id}.{args.cluster_domain}", host],
                    "secretName": secret_name,
                }
            ]
        }
    }


def create_ingress(route):
    meta, spec = route['metadata'], route['spec']
    namespace, name = meta["namespace"], meta["name"]

    ingress = make_ingress(route)

    if not ingress:
        # not enough data to create an Ingress
        return

    INFO(f'Creating ingress: {namespace}/{name}')
    DEBUG(JSON(ingress))

    api = kube.client.NetworkingV1Api()
    try:
        if args.dry_run:
            INFO(f'DRY_RUN: api.create_namespaced_ingress(namespace={namespace}, name={name}, body={ingress})')
        else:
            api.create_namespaced_ingress(namespace=namespace, body=ingress)
    except kube.client.exceptions.ApiException as ex:
        ERROR(f'Failed api call: create_namespaced_ingress(namespace={amespace}, name={name}, body={ingress}): {ex.status} {ex.reason}')

    return ingress


def patch_ingress(namespace, name, ingress):
    api = kube.client.NetworkingV1Api()
    # TODO: remove unnecessary fields prior patching
    try:
        if args.dry_run:
            INFO('DRY_RUN: api.patch_namespaced_ingress('
                f'namespace={namespace}, '
                f'name={name}, '
                'body={ingress})')
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

    if ingress['metadata'].get('annotations', {}).get(ANNOTATION_CERT_MANAGER_CLUSTER_ISSUER) != args.cluster_issuer:
        if 'annotations' not in ingress['metadata']:
            ingress['metadata']['annotations'] = {}
        ingress['metadata']['annotations'][ANNOTATION_CERT_MANAGER_CLUSTER_ISSUER] = args.cluster_issuer
        changed = True

    if changed:
        patch_ingress(ingress['metadata']['namespace'], ingress['metadata']['name'], ingress)


def delete_ingress(ingress):
    meta, spec = ingress['metadata'], ingress['spec']
    namespace, name = meta["namespace"], meta["name"]
    api = kube.client.NetworkingV1Api()

    INFO(f'Deleting ingress: {namespace}/{name}')
    try:
        if args.dry_run:
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

    ensure_ingress(ingress)


def handle_ingress_delete(meta, spec, ingress):
    CACHE.delete(meta)


########################################################################33


# TODO: unify both informers
class RouteInformer(Thread):
    def __init__(self, api_client, queue, stop_event):
        Thread.__init__(self, name="RouteInformer")
        self.api_instance = kube.client.CustomObjectsApi(api_client)
        self.queue = queue
        self.stop_event = stop_event

    def run(self):
        INFO(f"Starting {self.name} thread")
        resource_version = ""
        while True:
            while not self.stop_event.is_set():
                DEBUG("watch route")
                try:
                    self.watcher = kube.watch.Watch()
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
    def __init__(self, api_client, queue, stop_event):
        Thread.__init__(self, name="IngressInformer")
        self.api_instance = kube.client.NetworkingV1Api(api_client)
        self.queue = queue
        self.stop_event = stop_event

    def run(self):
        INFO(f"Starting {self.name} thread")
        resource_version = ""
        while True:
            while not self.stop_event.is_set():
                DEBUG("watch ingress")
                try:
                    self.watcher = kube.watch.Watch()
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
    global exit_count
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
    args = parser.parse_args()

    if args.verbose:
        log_level = logging.DEBUG
        log_fmt = f'time="%(asctime)s" pid=%(process)d file=%(funcName)s:%(lineno)d level=%(levelname)s message="%(message)s"'
    else:
        log_level = logging.INFO
        log_fmt = f'time="%(asctime)s" level=%(levelname)s message="%(message)s"'

    logging.basicConfig(format=log_fmt, level=log_level)

    if args.dry_run:
        INFO('Dry-run is active')

    if (args.ingress_class_name != DEFAULT_INGRESS_CLASS_NAME and not args.ignore_conflicting_ingress_class_name):
        ERROR("Setting --ingress-class-name may lead to infinite creation of ingresses/routes by openshift router controller.")
        ERROR("Please also set --ignore-conflicting-ingress-class-name if you known what you are doing.")
        sys.exit(1)

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

    if not args.cluster_domain:
        args.cluster_domain = discover_ingress_domain(api_client)
        INFO(f"Found Ingress domain: {args.ingress_class_name}")

    queue = Queue()
    stop_event = Event()

    ingress_informer = IngressInformer(api_client, queue, stop_event)
    ingress_informer.daemon = True
    ingress_informer.start()

    # give some time for Ingress to fill cache
    time.sleep(2)

    route_informer = RouteInformer(api_client, queue, stop_event)
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

        if (meta['namespace'] in args.ignored_namespaces) or (args.namespaces and meta['namespace'] not in args.namespaces):
            if meta['namespace'] not in args.ignored_namespaces:
                INFO(f'Ignoring namespace {meta["namespace"]}')
            args.ignored_namespaces.append(meta['namespace'])
            continue

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
