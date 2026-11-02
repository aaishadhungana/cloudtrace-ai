from app.engine.matching import is_broad_resource, matches_action, matches_resource


def test_action_matching_is_case_insensitive_and_supports_wildcards():
    assert matches_action("s3:GetObject", "S3:GETOBJECT")
    assert matches_action("s3:*", "s3:PutObject")
    assert matches_action("*", "iam:PassRole")
    assert matches_action("s3:Get*", "s3:GetObject")
    assert not matches_action("s3:Get*", "s3:PutObject")
    assert not matches_action("s3:*", "ec2:StartInstances")


def test_resource_matching_is_case_sensitive():
    assert matches_resource("arn:aws:s3:::reports", "arn:aws:s3:::reports")
    assert not matches_resource("arn:aws:s3:::reports", "arn:aws:s3:::REPORTS")


def test_resource_wildcards_stay_inside_the_pattern():
    assert matches_resource("arn:aws:s3:::acme-*", "arn:aws:s3:::acme-reports")
    assert matches_resource("arn:aws:s3:::acme-*/*", "arn:aws:s3:::acme-reports/*")
    assert not matches_resource("arn:aws:s3:::*", "arn:aws:ec2:us-east-1:111122223333:instance/i-1")
    assert not matches_resource("arn:aws:s3:::reports", "arn:aws:s3:::reports/*")


def test_regex_characters_in_patterns_are_literal():
    assert not matches_resource("arn:aws:s3:::a.c", "arn:aws:s3:::abc")
    assert matches_resource("arn:aws:s3:::a.c", "arn:aws:s3:::a.c")


def test_broad_resource_detection():
    targets = [
        "arn:aws:s3:::acme-reports",
        "arn:aws:s3:::acme-data",
        "arn:aws:s3:::other",
    ]
    assert is_broad_resource("*", targets)
    assert is_broad_resource("arn:aws:s3:::*", targets)
    assert is_broad_resource("arn:aws:s3:::acme-*", targets)
    assert not is_broad_resource("arn:aws:s3:::other", targets)
    assert not is_broad_resource("arn:aws:s3:::other/*", targets)


def test_pattern_matching_several_modeled_targets_is_broad():
    targets = ["arn:aws:iam::111122223333:role/a", "arn:aws:iam::111122223333:role/b"]
    assert is_broad_resource("arn:aws:iam::111122223333:role/*", targets)
    assert not is_broad_resource("arn:aws:iam::111122223333:role/a", targets)