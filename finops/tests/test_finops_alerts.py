"""Tests for the cost guardrails.

These run with no AWS account and no credentials. Every API call is served by
botocore's Stubber, which validates each request against the real service model - so a
misspelled parameter or a wrong shape fails here rather than at deploy time, which is
the whole reason the request builders are pure functions returning dicts.

What is deliberately NOT asserted: that the alerts fire. That needs real spend in a
real account over real time, and claiming it from a test would be claiming something
these tests cannot see.
"""

from __future__ import annotations

import os
import sys

import boto3
import pytest
from botocore.stub import ANY, Stubber

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import finops_alerts as fa

ACCOUNT = "123456789012"
TOPIC = f"arn:aws:sns:us-east-1:{ACCOUNT}:aws-cost-alerts"
# Real ARN shapes: botocore enforces a 20-character minimum on the CE ARN fields,
# so short placeholders fail request validation before the stub is ever reached.
MON_ARN = f"arn:aws:ce::{ACCOUNT}:anomalymonitor/11111111-2222-3333-4444-555555555555"
SUB_ARN = (f"arn:aws:ce::{ACCOUNT}:anomalysubscription/"
           "66666666-7777-8888-9999-000000000000")
SNS_SUB = (f"arn:aws:sns:us-east-1:{ACCOUNT}:aws-cost-alerts:"
           "abcdef12-3456-7890-abcd-ef1234567890")


# ------------------------------------------------------ pure request builders

def test_topic_policy_names_only_the_two_cost_services():
    pol = fa.topic_policy(TOPIC, ACCOUNT)
    services = pol["Statement"][0]["Principal"]["Service"]
    assert set(services) == {"budgets.amazonaws.com", "costalerts.amazonaws.com"}
    # Budgets and Cost Anomaly Detection publish to SNS directly. If this ever lists
    # events.amazonaws.com, someone has assumed the GuardDuty wiring applies here.
    assert "events.amazonaws.com" not in services


def test_topic_policy_is_scoped_to_this_account():
    pol = fa.topic_policy(TOPIC, ACCOUNT)
    cond = pol["Statement"][0]["Condition"]["StringEquals"]
    assert cond["aws:SourceAccount"] == ACCOUNT
    assert pol["Statement"][0]["Resource"] == TOPIC
    assert pol["Statement"][0]["Action"] == "sns:Publish"


def test_budget_excludes_credits_and_refunds():
    # A credit applied to the account would otherwise flatten the reported spend and
    # suppress an alarm that real usage should have triggered.
    b = fa.build_budget("monthly-account-cost", 20)
    assert b["CostTypes"]["IncludeCredit"] is False
    assert b["CostTypes"]["IncludeRefund"] is False
    assert b["TimeUnit"] == "MONTHLY"
    assert b["BudgetType"] == "COST"
    assert b["BudgetLimit"] == {"Amount": "20", "Unit": "USD"}


def test_notifications_cover_actual_and_forecast():
    n = fa.build_notifications(TOPIC, [50.0, 80.0, 100.0], [100.0])
    kinds = [x["Notification"]["NotificationType"] for x in n]
    assert kinds.count("ACTUAL") == 3
    assert kinds.count("FORECASTED") == 1
    for item in n:
        assert item["Subscribers"] == [{"SubscriptionType": "SNS", "Address": TOPIC}]
        assert item["Notification"]["ThresholdType"] == "PERCENTAGE"


def test_anomaly_threshold_is_absolute_dollars_not_percentage():
    # On a small account a percentage threshold fires on noise: $0.40 to $4 is +900%.
    expr = fa.build_threshold_expression(5.0)
    assert expr["Dimensions"]["Key"] == "ANOMALY_TOTAL_IMPACT_ABSOLUTE"
    assert expr["Dimensions"]["MatchOptions"] == ["GREATER_THAN_OR_EQUAL"]
    assert expr["Dimensions"]["Values"] == ["5.0"]


# ------------------------------------------------------------------ plan mode

def test_plan_sends_no_mutating_calls():
    r = fa.Runner(dry_run=True)
    r.call("budgets", "create_budget", AccountId=ACCOUNT, Budget={})
    r.call("sns", "subscribe", TopicArn=TOPIC, Protocol="email", Endpoint="a@b.c")
    assert len(r.planned) == 2
    assert [p["operation"] for p in r.planned] == ["create_budget", "subscribe"]
    # Nothing was sent, so no client was ever constructed.
    assert r._clients == {}


# -------------------------------------------------------- stubbed deploy path

class FakeSession:
    """Hands back pre-stubbed clients, so Runner talks to Stubber instead of AWS."""

    def __init__(self, clients):
        self._clients = clients

    def client(self, name, region_name=None):
        return self._clients[name]


@pytest.fixture
def stubs():
    sess = boto3.Session(
        aws_access_key_id="test", aws_secret_access_key="test", region_name="us-east-1"
    )
    clients, stubbers = {}, {}
    for name in ("sts", "sns", "budgets", "ce"):
        c = sess.client(name, region_name="us-east-1")
        s = Stubber(c)
        s.activate()
        clients[name], stubbers[name] = c, s
    yield clients, stubbers
    for s in stubbers.values():
        s.deactivate()


def test_deploy_creates_everything_when_nothing_exists(stubs, capsys):
    clients, sb = stubs

    sb["sts"].add_response("get_caller_identity", {"Account": ACCOUNT})

    sb["sns"].add_response("create_topic", {"TopicArn": TOPIC}, {"Name": "aws-cost-alerts"})
    sb["sns"].add_response("set_topic_attributes", {}, {
        "TopicArn": TOPIC, "AttributeName": "Policy", "AttributeValue": ANY})
    sb["sns"].add_response("list_subscriptions_by_topic", {"Subscriptions": []},
                           {"TopicArn": TOPIC})
    sb["sns"].add_response("subscribe", {"SubscriptionArn": SNS_SUB}, {
        "TopicArn": TOPIC, "Protocol": "email", "Endpoint": "adi@example.com"})

    # No budget yet, so the create path runs and must carry the notifications.
    sb["budgets"].add_client_error("describe_budget", service_error_code="NotFoundException")
    sb["budgets"].add_response("create_budget", {}, {
        "AccountId": ACCOUNT, "Budget": ANY, "NotificationsWithSubscribers": ANY})

    sb["ce"].add_response("get_anomaly_monitors", {"AnomalyMonitors": []})
    sb["ce"].add_response("create_anomaly_monitor", {"MonitorArn": MON_ARN},
                          {"AnomalyMonitor": ANY})
    sb["ce"].add_response("get_anomaly_subscriptions", {"AnomalySubscriptions": []})
    sb["ce"].add_response("create_anomaly_subscription", {"SubscriptionArn": SUB_ARN},
                          {"AnomalySubscription": ANY})
    sb["ce"].add_response("update_cost_allocation_tags_status", {"Errors": []},
                          {"CostAllocationTagsStatus": [
                              {"TagKey": "Project", "Status": "Active"},
                              {"TagKey": "Environment", "Status": "Active"}]})

    rc = fa.main(["deploy", "--email", "adi@example.com", "--monthly-limit", "20"],
                 session=FakeSession(clients))
    assert rc == 0
    for s in sb.values():
        s.assert_no_pending_responses()

    out = capsys.readouterr().out
    assert "budget         created" in out
    assert "monitor        created" in out
    assert "anomaly alert  created" in out
    assert "cost tags      active" in out


def test_deploy_is_idempotent_when_everything_exists(stubs, capsys):
    clients, sb = stubs

    sb["sts"].add_response("get_caller_identity", {"Account": ACCOUNT})
    sb["sns"].add_response("create_topic", {"TopicArn": TOPIC}, {"Name": "aws-cost-alerts"})
    sb["sns"].add_response("set_topic_attributes", {}, {
        "TopicArn": TOPIC, "AttributeName": "Policy", "AttributeValue": ANY})
    sb["sns"].add_response("list_subscriptions_by_topic",
                           {"Subscriptions": [{"Endpoint": "adi@example.com"}]},
                           {"TopicArn": TOPIC})

    # Budget present: update, and no second create.
    sb["budgets"].add_response("describe_budget", {"Budget": {
        "BudgetName": "monthly-account-cost",
        "BudgetLimit": {"Amount": "20", "Unit": "USD"},
        "TimeUnit": "MONTHLY", "BudgetType": "COST"}},
        {"AccountId": ACCOUNT, "BudgetName": "monthly-account-cost"})
    sb["budgets"].add_response("update_budget", {}, {"AccountId": ACCOUNT, "NewBudget": ANY})

    sb["ce"].add_response("get_anomaly_monitors", {"AnomalyMonitors": [
        {"MonitorArn": MON_ARN, "MonitorName": "service-spend-monitor",
         "MonitorType": "DIMENSIONAL"}]})
    sb["ce"].add_response("get_anomaly_subscriptions", {"AnomalySubscriptions": [
        {"SubscriptionArn": SUB_ARN, "SubscriptionName": "immediate-anomaly-alerts",
         "MonitorArnList": [MON_ARN], "Subscribers": [], "Frequency": "IMMEDIATE"}]})
    sb["ce"].add_response("update_cost_allocation_tags_status", {"Errors": []},
                          {"CostAllocationTagsStatus": ANY})

    rc = fa.main(["deploy", "--email", "adi@example.com"], session=FakeSession(clients))
    assert rc == 0
    for s in sb.values():
        s.assert_no_pending_responses()

    out = capsys.readouterr().out
    assert "subscription   exists" in out
    assert "budget         updated" in out
    assert "monitor        exists" in out
    assert "created" not in out.replace("subscription   exists", "")


def test_untaggable_key_is_reported_not_swallowed(stubs, capsys):
    # A tag key that has never been applied to a resource cannot be activated. That is
    # information worth printing, not an error to hide.
    clients, sb = stubs
    r = fa.Runner(session=FakeSession(clients))
    sb["ce"].add_response("update_cost_allocation_tags_status",
                          {"Errors": [{"TagKey": "Environment", "Code": "NotFound",
                                       "Message": "tag key not found"}]},
                          {"CostAllocationTagsStatus": ANY})
    fa.activate_cost_tags(r, ["Project", "Environment"])
    out = capsys.readouterr().out
    assert "cost tag       skipped  Environment" in out
    assert "cost tags      active   Project" in out


def test_teardown_refuses_without_confirmation(capsys):
    rc = fa.main(["teardown"], session=None)
    assert rc == 2
    assert "Refusing to delete without --yes" in capsys.readouterr().err


def test_plan_and_deploy_require_an_email(capsys):
    assert fa.main(["deploy"]) == 2
    assert "--email is required" in capsys.readouterr().err
