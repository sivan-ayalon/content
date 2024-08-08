#!/usr/bin/env python3
from datetime import datetime
import json
import os
from pathlib import Path
import pytest
import pytz
import requests_mock
from pytest_mock import MockerFixture
from typing import Any
from utils import (
    get_env_var,
    EnvVariableError,
    get_content_reviewers,
    CONTRIBUTION_REVIEWERS_KEY,
    CONTRIBUTION_SECURITY_REVIEWER_KEY,
    TIM_REVIEWER_KEY,
    DOC_REVIEWER_KEY,
    get_doc_reviewer,
    CONTENT_ROLES_BLOB_MASTER_URL,
    get_content_roles,
    CONTENT_ROLES_FILENAME,
    GITHUB_HIDDEN_DIR,
    write_deleted_summary_to_file,
    GH_JOB_SUMMARY_ENV_VAR,
    get_repo_owner_and_name,
    GH_REPO_ENV_VAR,
)
from purge_branch_protection_rules import (
    SUMMARY_HEADER as RULES_HEADER,
    SUMMARY_TABLE_HEADERS as RULES_TABLE_HEADERS,
    BranchProtectionRule
)
from purge_stale_branches import (
    SUMMARY_HEADER as STALE_HEADER,
    SUMMARY_TABLE_HEADERS as STALE_TABLE_HEADERS,
    StaleBranch,
    STALE_DAYS_AGO_ENV_VAR_DEFAULT
)
from git import Repo
import github


class TestGetEnvVar:
    def test_no_env_var(self):
        """
        Scenario: Try getting an environment variable

        Given
        - Using the 'get_env_var' function

        When
        - The environment variable does not exist
        - No 'default_val' argument was passed when the function was called

        Then
        - Ensure a 'EnvVariableError' exception is raised
        """
        with pytest.raises(EnvVariableError):
            get_env_var('MADE_UP_ENV_VARIABLE')

    def test_empty_env_var(self, monkeypatch):
        """
        Scenario: Try getting an environment variable

        Given
        - Using the 'get_env_var' function

        When
        - The environment variable's value is an empty string
        - No 'default_val' argument was passed when the function was called

        Then
        - Ensure a 'EnvVariableError' exception is raised
        """
        monkeypatch.setenv('MADE_UP_ENV_VARIABLE', '')
        with pytest.raises(EnvVariableError):
            get_env_var('MADE_UP_ENV_VARIABLE')

    def test_no_env_var_with_default(self):
        """
        Scenario: Try getting an environment variable

        Given
        - Using the 'get_env_var' function

        When
        - The environment variable does not exist
        - The 'default_val' argument was passed with a value of 'TIMOTHY'

        Then
        - Ensure 'TIMOTHY' is returned from the function
        """
        default_val = 'TIMOTHY'
        env_var_val = get_env_var('MADE_UP_ENV_VARIABLE', default_val)
        assert env_var_val == default_val

    def test_empty_env_var_with_default(self, monkeypatch):
        """
        Scenario: Try getting an environment variable

        Given
        - Using the 'get_env_var' function

        When
        - The environment variable's value is an empty string
        - The 'default_val' argument was passed with a value of 'TIMOTHY'

        Then
        - Ensure 'TIMOTHY' is returned from the function
        """
        monkeypatch.setenv('MADE_UP_ENV_VARIABLE', '')
        default_val = 'TIMOTHY'
        env_var_val = get_env_var('MADE_UP_ENV_VARIABLE', default_val)
        assert env_var_val == default_val

    def test_existing_env_var(self, monkeypatch):
        """
        Scenario: Try getting an environment variable

        Given
        - Using the 'get_env_var' function

        When
        - The environment variable's value is 'LEROY JENKINS'
        - No 'default_val' argument was passed when the function was called

        Then
        - Ensure 'LEROY JENKINS' is returned from the function
        """
        monkeypatch.setenv('MADE_UP_ENV_VARIABLE', 'LEROY JENKINS')
        env_var_val = get_env_var('MADE_UP_ENV_VARIABLE')
        assert env_var_val == 'LEROY JENKINS'

    def test_existing_env_var_with_default(self, monkeypatch):
        """
        Scenario: Try getting an environment variable

        Given
        - Using the 'get_env_var' function

        When
        - The environment variable's value is 'LEROY JENKINS'
        - The 'default_val' argument was passed with a value of 'TIMOTHY'

        Then
        - Ensure 'LEROY JENKINS' is returned from the function
        """
        monkeypatch.setenv('MADE_UP_ENV_VARIABLE', 'LEROY JENKINS')
        default_val = 'TIMOTHY'
        env_var_val = get_env_var('MADE_UP_ENV_VARIABLE', default_val)
        assert env_var_val == 'LEROY JENKINS'


@pytest.mark.parametrize(
    'content_roles,expected_content_reviewers,expected_security_reviewer, expected_tim_reviewer',
    [
        ({
            CONTRIBUTION_REVIEWERS_KEY: ["cr1", "cr2", "cr3", "cr4"],
            CONTRIBUTION_SECURITY_REVIEWER_KEY: ["sr1"],
            TIM_REVIEWER_KEY: "tr1",
            "CONTRIBUTION_TL": "tl1",
            "ON_CALL_DEVS": ["ocd1", "ocd2"]
        }, ["cr1", "cr2", "cr3", "cr4"], ["sr1"], "tr1")
    ]
)
def test_get_content_reviewers(
    content_roles: dict[str, Any],
    expected_content_reviewers: list[str],
    expected_security_reviewer: str,
    expected_tim_reviewer: str
):
    """
    Test retrieval of content and security reviewers.

    Given:
        - A ``dict[str, Any]``

    When:
        - 4 content reviewers and 1 security reviewers provided

    Then:
        - 4 content reviewers and 1 security reviewer added
    """

    actual_content_reviewers, actual_security_reviewer, actual_tim_reviewer = get_content_reviewers(content_roles)
    assert actual_content_reviewers == expected_content_reviewers
    assert actual_security_reviewer == expected_security_reviewer
    assert actual_tim_reviewer == expected_tim_reviewer


@pytest.mark.parametrize(
    'content_roles,expected_content_reviewers,expected_security_reviewer, expected_tim_reviewer',
    [
        ({
            CONTRIBUTION_REVIEWERS_KEY: ["cr1", "cr2", "cr3", "cr4"],
            CONTRIBUTION_SECURITY_REVIEWER_KEY: ["sr1", "sr2"],
            TIM_REVIEWER_KEY: "tr1",
            "CONTRIBUTION_TL": "tl1",
            "ON_CALL_DEVS": ["ocd1", "ocd2"]
        }, ["cr1", "cr2", "cr3", "cr4"], ["sr1", "sr2"], "tr1")
    ]
)
def test_get_content_reviewers_multiple_security(
    content_roles: dict[str, Any],
    expected_content_reviewers: list[str],
    expected_security_reviewer: str,
    expected_tim_reviewer: str
):
    """
    Test retrieval of content and security reviewers.

    Given:
        - A ``dict[str, Any]``

    When:
        - 4 content reviewers and 1 security reviewers provided

    Then:
        - 4 content reviewers and 1 security reviewer added
    """

    actual_content_reviewers, actual_security_reviewer, actual_tim_reviewer = get_content_reviewers(content_roles)
    assert actual_content_reviewers == expected_content_reviewers
    assert actual_security_reviewer == expected_security_reviewer
    assert actual_tim_reviewer == expected_tim_reviewer


@pytest.mark.parametrize(
    'content_roles',
    [
        ({
            CONTRIBUTION_REVIEWERS_KEY: [],
            CONTRIBUTION_SECURITY_REVIEWER_KEY: "sr1",
        }),
        ({
            CONTRIBUTION_REVIEWERS_KEY: ["cr1", "cr2"],
            CONTRIBUTION_SECURITY_REVIEWER_KEY: None,
        }),
        ({
            CONTRIBUTION_REVIEWERS_KEY: ["cr1", "cr2"],
            CONTRIBUTION_SECURITY_REVIEWER_KEY: "",
        }),
        ({
            CONTRIBUTION_REVIEWERS_KEY: "sr1",
            CONTRIBUTION_SECURITY_REVIEWER_KEY: "cr1",
        }),
        ({
            CONTRIBUTION_SECURITY_REVIEWER_KEY: ["sr1"],
        }),
        ({
            CONTRIBUTION_REVIEWERS_KEY: ["cr1"],
        }),
        ({
            "CONTRIBUTION_TL": "tl1",
            "ON_CALL_DEVS": ["ocd1", "ocd2"]
        })
    ]
)
def test_exit_get_content_reviewers(
    content_roles: dict[str, Any]
):
    """
    Test retrieval of content and security reviewers when the file/`dict`
    has unexpected/incorrect structure.

    Given:
        - A ``dict[str, Any]``

    When:
        - Case A: An empty contribution reviewers `list` is supplied.
        - Case B: An undefined security reviewer is supplied.
        - Case C: An empty security reviewer is supplied.
        - Case D: A `str` is supplied for the contribution reviewers.
        - Case E: No contribution reviewers key is supplied.
        - Case F: No security reviewer key is supplied.
        - Case G: No security reviewer key nor contribution reviewers key is supplied.

    Then:
        - Case A-G: Result in `sys.exit(1)`.
    """

    with pytest.raises(SystemExit) as e:
        get_content_reviewers(content_roles)
        assert e.type == SystemExit
        assert e.value.code == 1


@pytest.mark.parametrize(
    'content_roles,expected_doc_reviewer',
    [
        ({
            "CONTRIBUTION_REVIEWERS": ["cr1", "cr2", "cr3", "cr4"],
            "CONTRIBUTION_SECURITY_REVIEWER": "sr1",
            "CONTRIBUTION_TL": "tl1",
            "ON_CALL_DEVS": ["ocd1", "ocd2"],
            DOC_REVIEWER_KEY: "dr1"
        }, "dr1")
    ]
)
def test_get_doc_reviewer(
    content_roles: dict[str, Any],
    expected_doc_reviewer: str
):
    """
    Test retrieval of doc reviewer.

    Given:
        - A ``dict[str, Any]``

    When:
        - Case A: 4 content reviewers and 1 security reviewers provided, 1 doc reviewer
        - Case B: There's no ``DOC_REVIEWER`` key in `dict`.

    Then:
        - Case A: 1 doc reviewer returned.
        - Case B: `None`.
    """

    actual_doc_reviewer = get_doc_reviewer(content_roles)
    assert actual_doc_reviewer == expected_doc_reviewer


@pytest.mark.parametrize(
    'content_roles',
    [
        ({
            DOC_REVIEWER_KEY: [],
        }),
        ({
            "CONTRIBUTION_REVIEWERS": ["cr1", "cr2"],
        }),
        ({
            DOC_REVIEWER_KEY: ""
        }),
        ({
            DOC_REVIEWER_KEY: None
        })
    ]
)
def test_exit_get_doc_reviewer(
    content_roles: dict[str, Any]
):
    """
    Test retrieval of content and security reviewers when the file/`dict`
    has unexpected/incorrect structure.
    Given:
        - A ``dict[str, Any]``
    When:
        - Case A: Document reviewer specified as an array/list.
        - Case B: Document reviewer key is not specified.
        - Case C: Document reviewer is empty.
        - Case D: Document reviewer is undefined.
    Then:
        - Case A-G: Result in `sys.exit(1)`.
    """

    with pytest.raises(ValueError) as e:
        get_doc_reviewer(content_roles)
        assert e.type == ValueError


class TestGetContentRoles:

    content_roles: dict[str, Any] = {
        CONTRIBUTION_REVIEWERS_KEY: ['prr1', 'prr2', 'prr3'],
        'CONTRIBUTION_TL': 'tl1',
        CONTRIBUTION_SECURITY_REVIEWER_KEY: 'sr1',
        'ON_CALL_DEVS': ['ocd1', 'ocd2'],
        DOC_REVIEWER_KEY: 'dr1',
        TIM_REVIEWER_KEY: 'tr1'
    }

    def test_get_content_roles_success(
        self,
        requests_mock: requests_mock.Mocker
    ):
        """
        Test successful retrieval of content_roles.json.

        Given:
        - A content_roles.json

        When:
        - The request to retrieve content_roles.json is successful.

        Then:
        - The response includes the expected content role keys.
        """

        requests_mock.get(
            CONTENT_ROLES_BLOB_MASTER_URL,
            json=self.content_roles
        )

        actual_content_roles = get_content_roles()
        assert actual_content_roles
        assert CONTRIBUTION_REVIEWERS_KEY in actual_content_roles
        assert CONTRIBUTION_SECURITY_REVIEWER_KEY in actual_content_roles
        assert TIM_REVIEWER_KEY in actual_content_roles

    def test_get_content_roles_fail_blob(
        self,
        requests_mock: requests_mock.Mocker,
        tmp_path: Path
    ):
        """
        Test failure to retrieve the content_roles.json blob
        and successful retrieval from the filesystem.

        Given:
        - A content_roles.json

        When:
        - The request to retrieve content_roles.json is fails.

        Then:
        - get_content_roles returns a populated dict.
        """

        # Mock failed request
        requests_mock.get(
            CONTENT_ROLES_BLOB_MASTER_URL,
            status_code=404
        )

        # Create repo and content_roles.json in fs
        Repo.init(tmp_path)
        (tmp_path / GITHUB_HIDDEN_DIR).mkdir()
        content_roles_path = tmp_path / GITHUB_HIDDEN_DIR / CONTENT_ROLES_FILENAME
        content_roles_path.touch()
        content_roles_path.write_text(json.dumps(self.content_roles, indent=4))

        actual_content_roles = get_content_roles(tmp_path)

        assert actual_content_roles
        assert CONTRIBUTION_REVIEWERS_KEY in actual_content_roles
        assert CONTRIBUTION_SECURITY_REVIEWER_KEY in actual_content_roles
        assert TIM_REVIEWER_KEY in actual_content_roles

    def test_get_content_roles_invalid_json_blob(
        self,
        requests_mock: requests_mock.Mocker,
        tmp_path: Path
    ):
        """
        Test failure to retrieve content_roles.json
        and successful retrieval from the filesystem.

        Given:
        - A content_roles.json

        When:
        - The content_roles.json is invalid.

        Then:
        - get_content_roles returns a populated dict.
        """

        requests_mock.get(
            CONTENT_ROLES_BLOB_MASTER_URL,
            json={"only_key"}
        )

        # Create repo and content_roles.json in fs
        Repo.init(tmp_path)
        (tmp_path / GITHUB_HIDDEN_DIR).mkdir()
        content_roles_path = tmp_path / GITHUB_HIDDEN_DIR / CONTENT_ROLES_FILENAME
        content_roles_path.touch()
        content_roles_path.write_text(json.dumps(self.content_roles, indent=4))

        actual_content_roles = get_content_roles(tmp_path)

        assert actual_content_roles
        assert CONTRIBUTION_REVIEWERS_KEY in actual_content_roles
        assert CONTRIBUTION_SECURITY_REVIEWER_KEY in actual_content_roles
        assert TIM_REVIEWER_KEY in actual_content_roles

    def test_get_content_roles_invalid_json_blob_and_fs(
        self,
        requests_mock: requests_mock.Mocker,
        tmp_path: Path
    ):
        """
        Test failure to retrieve content_roles.json
        from the blob and from the filesystem.

        Given:
        - A content_roles.json

        When:
        - The content_roles.json is invalid in blob.
        - The content_roles.json is invalid in filesystem.

        Then:
        - get_content_roles returns nothing.
        """

        requests_mock.get(
            CONTENT_ROLES_BLOB_MASTER_URL,
            json={"only_key"}
        )

        # Create repo and content_roles.json in fs
        Repo.init(tmp_path)
        (tmp_path / GITHUB_HIDDEN_DIR).mkdir()
        content_roles_path = tmp_path / GITHUB_HIDDEN_DIR / CONTENT_ROLES_FILENAME
        content_roles_path.touch()
        content_roles_path.write_text("{\"only_key\"}")

        actual_content_roles = get_content_roles(tmp_path)

        assert not actual_content_roles


class TestWriteSummary:
    @pytest.fixture(autouse=True)
    def setup(self, mocker: MockerFixture, tmp_path: Path):

        summary = tmp_path / "summary.md"
        summary.touch()

        mocker.patch.dict(os.environ, {
            GH_JOB_SUMMARY_ENV_VAR: str(summary)
        })

    def test_md_summary_output_purge_protection_rules(
        self,
        tmp_path: Path
    ):
        """
        Test the output of the summary file generated
        for purging branch protection rules.

        Given:
        - A temporary directory.

        When:
        - The `GITHUB_STEP_SUMMARY` env var is set to the temporary directory.
        - A rule is deleted.

        Then:
        - The summary file exists in the temporary directory.
        - The summary includes the rule that was deleted.
        """

        summary_file_path = tmp_path / "summary.md"
        deleted: list[BranchProtectionRule] = []

        for i in range(10):
            deleted.append(
                BranchProtectionRule(
                    str(i),
                    f"{i}/*",
                    matching_refs=0,
                    deleted=True
                )
            )

        write_deleted_summary_to_file(
            header=RULES_HEADER,
            table_headers=RULES_TABLE_HEADERS,
            table_rows=[[rule.id, rule.pattern, rule.matching_refs, rule.deleted, rule.error] for rule in deleted]
        )

        assert summary_file_path.exists()
        actual_summary_lines = summary_file_path.read_text().splitlines()
        assert actual_summary_lines[0] == RULES_HEADER
        assert len(actual_summary_lines) == 14
        assert "1/*" in actual_summary_lines[5]

    def test_md_summary_output_no_deleted_rules(
            self,
            mocker: MockerFixture,
            tmp_path: Path
    ):
        """
        Test the output of the summary file generated
        when there were no deleted rules.

        Given:
        - A temporary directory.

        When:
        - The `GITHUB_STEP_SUMMARY` env var is set to the temporary directory.
        - No rules have been deleted.

        Then:
        - The summary file exists in the temporary directory.
        - The summary includes a message indicating rules have
        not been deleted.
        """

        summary_file_path = tmp_path / "summary.md"
        summary_file_path.touch()
        mocker.patch.dict(os.environ, {GH_JOB_SUMMARY_ENV_VAR: str(summary_file_path)})

        deleted: list[BranchProtectionRule] = []

        write_deleted_summary_to_file(
            header=RULES_HEADER,
            table_headers=RULES_TABLE_HEADERS,
            table_rows=[[rule.id, rule.pattern, rule.matching_refs, rule.deleted, rule.error] for rule in deleted]
        )

        assert summary_file_path.exists()
        actual_summary_lines = summary_file_path.read_text().splitlines()
        assert len(actual_summary_lines) == 4
        assert actual_summary_lines[0] == RULES_HEADER

    def test_md_summary_output_no_deleted_rules_2(
            self,
            tmp_path: Path
    ):
        """
        Test the output of the summary file generated
        when there was a list of processed rules
        but none of them were deleted.

        Given:
        - A temporary directory.

        When:
        - The `GITHUB_STEP_SUMMARY` env var is set to the temporary directory.
        - No rules have been deleted.

        Then:
        - The summary file exists in the temporary directory.
        - The summary includes a message indicating rules have
        not been deleted.
        """

        summary_file_path = tmp_path / "summary.md"

        request_status_code_1 = 400
        request_message_1 = "some client-side error"
        request_status_code_2 = 404
        request_message_2 = "Not found"

        processed: list[BranchProtectionRule] = [
            BranchProtectionRule(
                id="1",
                pattern="abcd",
                matching_refs=0,
                deleted=False,
                error=github.GithubException(
                    status=request_status_code_1,
                    data=request_message_1,
                    headers={"x-gh-header": "mock"}
                )
            ),
            BranchProtectionRule(
                id="2",
                pattern="abce",
                matching_refs=0,
                deleted=False,
                error=github.GithubException(
                    status=request_status_code_2,
                    data=request_message_2,
                    headers={"x-gh-header": "mock"}
                )
            )
        ]

        write_deleted_summary_to_file(
            header=RULES_HEADER,
            table_headers=RULES_TABLE_HEADERS,
            table_rows=[[rule.id, rule.pattern, rule.matching_refs, rule.deleted, rule.error] for rule in processed]
        )

        assert summary_file_path.exists()
        actual_summary_lines = summary_file_path.read_text().splitlines()
        assert actual_summary_lines[0] == RULES_HEADER
        assert len(actual_summary_lines) == 6
        assert f"{request_status_code_1} \"{request_message_1}\"" in actual_summary_lines[4]
        assert f"{request_status_code_2} \"{request_message_2}\"" in actual_summary_lines[5]

    def test_md_summary_output_purge_branch(
        self,
        tmp_path: Path
    ):
        """
        Test the output of the summary file generated
        for purging branch protection rules.

        Given:
        - A temporary directory.

        When:
        - The `GITHUB_STEP_SUMMARY` env var is set to the temporary directory.
        - A rule is deleted.

        Then:
        - The summary file exists in the temporary directory.
        - The summary includes the rule that was deleted.
        """

        summary_file_path = tmp_path / "summary.md"

        deleted: list[StaleBranch] = []

        for i in range(10):
            deleted.append(
                StaleBranch(
                    name=f"{i}_branch",
                    last_committed_date=datetime.now(tz=pytz.utc),
                    deleted=True
                )
            )

        header = STALE_HEADER.format(
            count=len(deleted),
            days_ago=STALE_DAYS_AGO_ENV_VAR_DEFAULT
        )

        write_deleted_summary_to_file(
            header=header,
            table_headers=STALE_TABLE_HEADERS,
            table_rows=[[branch.name, branch.get_last_committed_date(), branch.deleted, branch.error] for branch in deleted]
        )

        assert summary_file_path.exists()
        actual_summary_lines = summary_file_path.read_text().splitlines()
        assert actual_summary_lines[0] == header
        assert len(actual_summary_lines) == 14
        assert "0_branch" in actual_summary_lines[4]

    def test_md_summary_output_no_stale_branches(
            self,
            tmp_path: Path
    ):
        """
        Test the output of the summary file generated
        when there were no deleted rules.

        Given:
        - A temporary directory.

        When:
        - The `GITHUB_STEP_SUMMARY` env var is set to the temporary directory.
        - No rules have been deleted.

        Then:
        - The summary file exists in the temporary directory.
        - The summary includes a message indicating rules have
        not been deleted.
        """

        summary_file_path = tmp_path / "summary.md"

        deleted: list[StaleBranch] = []

        header = STALE_HEADER.format(
            count=len(deleted),
            days_ago=STALE_DAYS_AGO_ENV_VAR_DEFAULT
        )

        write_deleted_summary_to_file(
            header=header,
            table_headers=STALE_TABLE_HEADERS,
            table_rows=[[branch.name, branch.get_last_committed_date(), branch.deleted, branch.error]
                        for branch in deleted]
        )

        assert summary_file_path.exists()
        actual_summary_lines = summary_file_path.read_text().splitlines()
        assert len(actual_summary_lines) == 4
        assert actual_summary_lines[0] == header

    def test_md_summary_output_no_stale_branches_2(
            self,
            tmp_path: Path
    ):
        """
        Test the output of the summary file generated
        when there was a list of processed rules
        but none of them were deleted.

        Given:
        - A temporary directory.

        When:
        - The `GITHUB_STEP_SUMMARY` env var is set to the temporary directory.
        - No rules have been deleted.

        Then:
        - The summary file exists in the temporary directory.
        - The summary includes a message indicating rules have
        not been deleted.
        """

        summary_file_path = tmp_path / "summary.md"

        request_status_code_1 = 400
        request_message_1 = "some client-side error"
        request_status_code_2 = 404
        request_message_2 = "Not found"

        processed: list[StaleBranch] = [
            StaleBranch(
                name="1",
                last_committed_date=datetime.now(tz=pytz.utc),
                deleted=False,
                error=github.GithubException(
                    status=request_status_code_1,
                    data=request_message_1,
                    headers={"gh-mock-header": "mock"}
                )
            ),
            StaleBranch(
                name="2",
                last_committed_date=datetime.now(tz=pytz.utc),
                deleted=False,
                error=github.GithubException(
                    status=request_status_code_2,
                    data=request_message_2,
                    headers={"gh-mock-header": "mock"}
                )
            )
        ]

        header = STALE_HEADER.format(
            count=len(processed),
            days_ago=STALE_DAYS_AGO_ENV_VAR_DEFAULT
        )

        write_deleted_summary_to_file(
            header=header,
            table_headers=STALE_TABLE_HEADERS,
            table_rows=[[branch.name, branch.get_last_committed_date(), branch.deleted, branch.error] for branch in processed]
        )

        assert summary_file_path.exists()
        actual_summary_lines = summary_file_path.read_text().splitlines()
        assert actual_summary_lines[0] == header
        assert len(actual_summary_lines) == 6
        assert f"{request_status_code_1} \"{request_message_1}\"" in actual_summary_lines[4]
        assert f"{request_status_code_2} \"{request_message_2}\"" in actual_summary_lines[5]


class TestRepoOwnerName:
    """
    Test class for the functionality of `utils.get_repo_owner_and_name`
    method.
    """

    def test_valid_repo(self, mocker: MockerFixture):
        """
        Given:
        - A repo owner.
        - A repo name.

        When:
        - The environmental variable is set with owner and name.

        Then:
        - The expected repo name and owner are returned.
        """

        expected_repo_owner = "me"
        expected_repo_name = "my_repo"
        mocker.patch.dict(
            os.environ,
            {
                GH_REPO_ENV_VAR: f"{expected_repo_owner}/{expected_repo_name}"
            }
        )

        actual_owner, actual_repo_name = get_repo_owner_and_name()

        assert actual_owner == expected_repo_owner
        assert actual_repo_name == expected_repo_name

    def test_invalid_repo(self, mocker: MockerFixture):
        """
        Given:
        - A repo owner.
        - A repo name.
        - A repo submodule.

        When:
        - The environmental variable is set with owner, name and submodule.

        Then:
        - A `ValueError` is thrown with expected message.
        """

        expected_repo_owner = "me"
        expected_repo_name = "my_repo/submodule"
        mocker.patch.dict(
            os.environ,
            {
                GH_REPO_ENV_VAR: f"{expected_repo_owner}/{expected_repo_name}"
            }
        )

        with pytest.raises(ValueError, match="Input string must be in the format 'owner/repository'."):
            get_repo_owner_and_name()

    def test_env_var_not_set(self):
        """
        Given:
        - Nothing.

        When:
        - The environmental variable is not set.

        Then:
        - An `OSError` is thrown with expected message.
        """

        with pytest.raises(OSError, match=f"Environmental variable '{GH_REPO_ENV_VAR}' not set"):
            get_repo_owner_and_name()
