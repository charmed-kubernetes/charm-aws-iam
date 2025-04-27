#!/usr/bin/env python

import base64
import json
import os
import random
import string
from subprocess import CalledProcessError, check_output

from charmhelpers.core import hookenv
from charmhelpers.core.templating import render
from charms.layer import tls_client
from charms.leadership import leader_get, leader_set
from charms.reactive import (
    clear_flag,
    endpoint_from_flag,
    hook,
    is_flag_set,
    set_flag,
    when,
    when_not,
)

namespace = "kube-system"
secret_yaml = "/root/cdk/addons/aws-iam-secret.yaml"
deployment_yaml = "/root/cdk/addons/aws-iam-deployment.yaml"
service_yaml = "/root/cdk/addons/aws-iam-service.yaml"
webhook_path = "/root/cdk/aws-iam-webhook.yaml"


# This charm sets up AWS-IAM auth on the cluster. It is a
# subordinate charm to the k8s master. It does the following:
# 1) Wait for apiserver to become available(endpoint.aws-iam.available)
# 2) Leader deploys service for aws-iam. This gives us
#    the IP address to put into a certificate.
# 3) Leader requests certificate for that service IP.
# 4) Leader puts the cert data into leadership data as each
#    unit needs to write this information into the webhook
#    config for the api server.
# 5) Leader deploys certificate as a secret along with the
#    rest of webhook yaml including pod
# 6) All units then generate webhook config for api server
# 7) Flag set to tell the api server that things are ready
# 8) api server will restart and use webhook.

# Every unit uses the leadership data to write the webhook yaml
# file and tell the master that it was done via the aws-iam
# interface call to set_webhook_status.


def _kubectl(*args):
    """Run a kubectl cli command with a config file. Returns stdout and throws
    an error if the command fails."""
    command = ["/snap/bin/kubectl", "--kubeconfig=" + "/root/.kube/config"] + list(args)
    hookenv.log("Executing {}".format(command))
    return check_output(command)


def _get_cert_common_name():
    return "aws-iam.{}.svc".format(namespace)


def _get_service_ip(service, namespace="kube-system"):
    try:
        output = _kubectl(
            "get", "service", "--namespace", namespace, service, "--output", "json"
        )
    except CalledProcessError as e:
        hookenv.log(e)
        hookenv.log("Failed to get service IP for aws iam service!")
    svc = json.loads(output)
    return svc["spec"]["clusterIP"]


def _remove_service():
    if is_flag_set("charm.aws-iam.deployed-service"):
        hookenv.log("Cleaning up service...")
        if is_flag_set("endpoint.aws-iam.available"):
            try:
                _kubectl("delete", "-f", secret_yaml)
            except CalledProcessError as e:
                hookenv.log(e)
                hookenv.log(
                    "Failed to delete AWS_IAM service. Will attempt again next update."
                )  # noqa
                return

        clear_flag("charm.aws-iam.deployed-service")


def _remove_certificate():
    if is_flag_set("charm.aws-iam.certificate-written"):
        hookenv.log("Cleaning up secret...")
        if is_flag_set("endpoint.aws-iam.available"):
            try:
                _kubectl("delete", "-f", secret_yaml)
            except CalledProcessError as e:
                hookenv.log(e)
                hookenv.log(
                    "Failed to delete AWS_IAM secret. Will attempt again next update."
                )  # noqa
                return

        clear_flag("charm.aws-iam.certificate-written")
    clear_flag("charm.aws-iam.certificate-requested")


def _remove_deployment():
    if is_flag_set("charm.aws-iam.deployment-started"):
        hookenv.log("Cleaning up deployment...")
        try:
            _kubectl("delete", "-f", deployment_yaml)
        except CalledProcessError as e:
            hookenv.log(e)
            hookenv.log(
                "Failed to delete AWS_IAM deployment. Will attempt again next update."
            )  # noqa
            return
        clear_flag("charm.aws-iam.deployment-started")


def _remove_webhook():
    if is_flag_set("charm.aws-iam.written-wehbook"):
        if os.path.isfile(webhook_path):
            hookenv.log("Removing file: " + webhook_path)
            os.remove(webhook_path)


@hook("pre-series-upgrade")
def pre_series_upgrade():
    hookenv.status_set("blocked", "Series upgrade in progress")


@when_not("endpoint.aws-iam.available", "charm.aws-iam.deployed-service")
@when_not("upgrade.series.in-progress")
def waiting_for_api():
    hookenv.status_set("waiting", "Waiting for API server to become availble")


@when("endpoint.aws-iam.available")
@when_not("charm.aws-iam.deployed-service")
def deploy_service():
    hookenv.status_set("maintenance", "Deploying aws-iam service")
    context = {}
    context["namespace"] = namespace
    render("service.yaml", service_yaml, context)
    try:
        _kubectl("apply", "-f", service_yaml)
    except CalledProcessError as e:
        hookenv.status_set("maintenance", "Unable to deploy service. Will retry.")
        hookenv.log(e)
        hookenv.log(
            "Failed to create AWS_IAM service. Will attempt again next update."
        )  # noqa
        return
    set_flag("charm.aws-iam.deployed-service")


@when("endpoint.aws-iam.available", "charm.aws-iam.deployed-service")
@when_not("certificates.available")
@when_not("upgrade.series.in-progress")
def waiting_for_certificate_relation():
    try:
        goal_state = hookenv.goal_state()
    except NotImplementedError:
        goal_state = {}

    if "certificates" in goal_state.get("relations", {}):
        hookenv.status_set(
            "waiting", "Waiting for certificate relation to become ready"
        )
    else:
        hookenv.status_set("waiting", "Requires certificate relation established")


@when(
    "certificates.available",
    "charm.aws-iam.deployed-service",
    "endpoint.aws-iam.available",
)
@when_not("leadership.set.cert")
@when_not("upgrade.series.in-progress")
def waiting_for_leadership_data():
    hookenv.status_set("waiting", "Waiting for certificate to become available")


@when("endpoint.aws-iam.available", "charm.aws-iam.deployed-service")
@when("certificates.available", "leadership.is_leader")
@when_not("charm.aws-iam.certificate-requested", "leader.set.cert")
@when_not("upgrade.series.in-progress")
def request_certificate():
    """Send the data that is required to create a server certificate for
    the webhook payload. Note that only the leader requests a certificate.
    This is then shared across leadership data with the other units."""

    # this won't work without a service IP, check that first
    service_ip = _get_service_ip("aws-iam-authenticator")
    if not service_ip:
        hookenv.status_set("maintenance", "Waiting for service")
        return

    hookenv.status_set("maintenance", "Requesting certificates")

    leader_set({"service_ip": service_ip})

    # Use the public ip of this unit as the Common Name for the certificate.
    common_name = _get_cert_common_name()

    # Create SANs that the tls layer will add to the server cert.
    sans = [service_ip, "aws-iam", "aws-iam.{}".format(namespace)]

    # Request a server cert with this information.
    tls_client.request_server_cert(common_name, sorted(set(sans)))
    set_flag("charm.aws-iam.certificate-requested")


@when("tls_client.certs.changed")
def process_cert_change():
    clear_flag("charm.aws-iam.certificate-written")
    clear_flag("tls_client.certs.changed")


@when("certificates.server.certs.available", "leadership.is_leader")
@when_not("leadership.set.cert")
def write_cert_to_leadership_data():
    cert_ep = endpoint_from_flag("certificates.certs.available")
    my_cert = cert_ep.server_certs_map[_get_cert_common_name()]

    leader_set({"cert": my_cert.cert, "key": my_cert.key})
    # we also use this time to generate the cluster id
    if not leader_get("cluster_id"):
        cluster_id = "".join(
            random.choice(string.ascii_letters + string.digits) for i in range(24)
        )
        leader_set({"cluster_id": cluster_id})


@when("leadership.set.cluster_id", "endpoint.aws-iam.available")
@when_not("charm.aws-iam.published-cluster-id")
def publish_cluster_id():
    aws_iam = endpoint_from_flag("endpoint.aws-iam.available")
    aws_iam.set_cluster_id(leader_get("cluster_id"))
    set_flag("charm.aws-iam.published-cluster-id")


@when("leadership.set.cert", "leadership.is_leader", "endpoint.aws-iam.available")
@when_not("charm.aws-iam.certificate-written")
@when_not("upgrade.series.in-progress")
def write_cert_secret():
    """Write returned certificate into a secret for the webhook.
    This data is also shared across the leadership data to other
    units."""
    hookenv.status_set("maintenance", "Writing certificates")

    cert = leader_get("cert").encode("utf-8")
    key = leader_get("key").encode("utf-8")

    context = {}
    context["namespace"] = namespace
    context["cert"] = base64.b64encode(cert).decode("utf-8")
    context["key"] = base64.b64encode(key).decode("utf-8")

    render("certs.yaml", secret_yaml, context)
    hookenv.log("Updating AWS-IAM secret.")
    try:
        _kubectl("apply", "-f", secret_yaml)
    except CalledProcessError as e:
        hookenv.log(e)
        hookenv.log(
            "Failed to create AWS_IAM secret. Will attempt again next update."
        )  # noqa
        return

    set_flag("charm.aws-iam.certificate-written")


@when("config.changed.image")
def regenerate_deployment():
    clear_flag("charm.aws-iam.deployment-started")


@when("leadership.set.cert", "leadership.is_leader", "endpoint.aws-iam.available")
@when_not("charm.aws-iam.deployment-started")
def apply_webhook_deployment():
    hookenv.status_set("maintenance", "Deploying webhook")
    context = {}
    context["namespace"] = namespace
    context["cluster_id"] = leader_get("cluster_id")
    context["image"] = hookenv.config("image")
    render("aws-iam-deployment.yaml", deployment_yaml, context)
    try:
        _kubectl("apply", "-f", deployment_yaml)
    except CalledProcessError as e:
        hookenv.status_set("maintenance", "Unable to deploy webhook. Will retry.")
        hookenv.log(e)
        hookenv.log(
            "Failed to create AWS_IAM deployment. Will attempt again next update."
        )  # noqa
        return
    set_flag("charm.aws-iam.deployment-started")


@when("leadership.set.cert", "endpoint.aws-iam.available", "leadership.set.service_ip")
@when_not("charm.aws-iam.written-webhook")
def write_webhook_yaml():
    """Write out the webhook yaml file for the api server to use.
    Everyone, including the leader, does this with leadership data
    set by the leader."""
    hookenv.status_set("maintenance", "Writing apiserver webhook configuration")
    context = {}
    cert = leader_get("cert").encode("utf-8")
    context["cert"] = base64.b64encode(cert).decode("utf-8")
    context["service_ip"] = leader_get("service_ip")
    render("webhook.yaml", webhook_path, context)
    aws_iam = endpoint_from_flag("endpoint.aws-iam.available")
    aws_iam.set_webhook_status(True)
    set_flag("charm.aws-iam.written-webhook")


@when("leadership.set.cert")
@when_not("endpoint.aws-iam.available")
@when_not("upgrade.series.in-progress")
def waiting():
    hookenv.status_set("waiting", "Waiting for API server to become available")


@when(
    "charm.aws-iam.written-webhook",
    "charm.aws-iam.deployment-started",
    "leadership.is_leader",
)
@when_not("upgrade.series.in-progress")
def leader_ready():
    try:
        output = _kubectl("get", "po", "-n", namespace, "--output", "json")
        out_list = json.loads(output)
        aws_auth_pods = [
            pod
            for pod in out_list["items"]
            if "aws-iam-authenticator" in pod["metadata"]["name"]
        ]
        not_running = [
            pod
            for pod in aws_auth_pods
            if (
                pod["status"]["phase"] != "Running"
                and pod["status"].get("reason", "") != "Evicted"
            )
            or not all(
                [container["ready"] for container in pod["status"]["containerStatuses"]]
            )
        ]  # noqa

        pending = [pod for pod in aws_auth_pods if pod["status"]["phase"] == "Pending"]

        if len(pending) > 0:
            hookenv.status_set("maintenance", "Waiting for aws iam pod to start")
        elif len(not_running) > 0:
            if len(not_running) == 1:
                msg = "Waiting for {} to start"
                msg = msg.format(not_running[0]["metadata"]["name"])
                hookenv.status_set("maintenance", msg)
            else:
                msg = "Waiting for {} pods to start".format(len(not_running))
                hookenv.status_set("maintenance", msg)
        elif len(aws_auth_pods) == 0:
            msg = "Waiting for pods to be created"
            hookenv.status_set("maintenance", msg)
        else:
            hookenv.status_set("active", "Ready")
    except CalledProcessError as e:
        hookenv.log(e)
        hookenv.log("failed to get aws-iam-authenticator pod status")
        hookenv.status_set("maintenance", "Waiting for aws iam pod")


@when("charm.aws-iam.written-webhook")
@when_not("leadership.is_leader")
@when_not("upgrade.series.in-progress")
def non_leader_ready():
    hookenv.status_set("active", "Ready")


@when("leader.set.cert")
@when_not("certificates.available")
def nuke_certs():
    """If the certificate relation is broken, we need to forget about
    our certificates and wait for new ones."""
    hookenv.status_set("maintenance", "Removing until certificate relation established")
    is_leader = is_flag_set("leadership.is_leader")
    if is_leader:
        leader_set({"cert": None, "key": None})
        _remove_certificate()
        _remove_deployment()
    _remove_webhook()


@when("leader.set.service_ip")
@when_not("endpoint.aws-iam.available")
def api_server_broken():
    try:
        goal_state = hookenv.goal_state()
    except NotImplementedError:
        goal_state = {}

    # just a blip if the goal state still has it.
    if "aws-iam" in goal_state.get("relations", {}):
        return

    # forget all the things. The service IP will change
    # if we lose our cluster, which will domino into everything
    is_leader = is_flag_set("leadership.is_leader")
    if is_leader:
        leader_set({"cert": None, "key": None, "service_ip": None})
        _remove_service()
        _remove_certificate()
        _remove_deployment()

    _remove_webhook()
