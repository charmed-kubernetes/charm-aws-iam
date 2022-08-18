import importlib

aws_iam = importlib.import_module('aws-iam')


def test_series_upgrade():
    assert aws_iam.hookenv.status_set.call_count == 0
    aws_iam.pre_series_upgrade()
    assert aws_iam.hookenv.status_set.call_count == 1
