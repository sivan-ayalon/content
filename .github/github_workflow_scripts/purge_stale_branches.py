from dataclasses import dataclass
import datetime
from pathlib import Path
import sys
from git import Repo
import github
from utils import (
    get_logger,
    write_deleted_summary_to_file,
    get_env_var,
    get_token,
    get_repo_owner_and_name,
    get_repo_path
)

logger = get_logger(f"{Path(__file__).stem}")

REMOTE_NAME = "origin"
PROTECTED_BRANCHES = ["master", "main"]

SUMMARY_HEADER = "## Deleted {count} Stale Branches ({days_ago} Days Ago)"
SUMMARY_TABLE_HEADERS = ["Name", "Last Committed Date", "Deleted", "Error"]

STALE_DAYS_AGO_ENV_VAR_KEY = "STALE_DAYS_AGO"
STALE_DAYS_AGO_ENV_VAR_DEFAULT = '30'
LIMIT_ENV_VAR = "PURGE_LIMIT"
LIMIT_ENV_VAR_DEFAULT = "100"


@dataclass
class StaleBranch:
    name: str
    last_committed_date: datetime.datetime
    deleted: bool | None = None
    error: github.GithubException | None = None

    def __str__(self) -> str:
        date_str = self.last_committed_date.strftime('%Y %B %d %H:%M:%S')
        return f"StaleBranche(name='{self.name}', last_committed_date='{date_str} (UTC)', deleted='{self.deleted}, error='{self.error}')"  # noqa: E501

    def get_last_committed_date(self) -> str:
        return self.last_committed_date.strftime('%Y %B %d %H:%M:%S')


def get_stale_branches(repo: Repo, days: int, limit: int = 100) -> list[StaleBranch]:
    """
    Retrieve the stale branches from the git filesystem.

    Arguments:
    - `repo` (``git.Repo``): The repository in the filesystem to search for
    the stale branches.
    - `days` (``int``): The days to search for stale branches from until today.
    - `limit` (``int``): The limit to the number of stale branches.

    Returns:
    - `list[StaleBranch]`
    """

    cutoff_date = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=days)
    logger.info(f"{cutoff_date=}")
    stale_branches: list[StaleBranch] = []

    for ref in repo.remotes.origin.refs:
        if ref.remote_head == 'HEAD':
            continue
        commit_date = ref.commit.committed_datetime
        if commit_date < cutoff_date:
            stale_branches.append(
                StaleBranch(
                    name=ref.remote_head,
                    last_committed_date=commit_date
                )
            )
            if len(stale_branches) == limit:
                break

    return stale_branches


def main():

    try:
        token = get_token()
        owner, repo_name = get_repo_owner_and_name()
        days = int(get_env_var(STALE_DAYS_AGO_ENV_VAR_KEY, STALE_DAYS_AGO_ENV_VAR_DEFAULT))
        limit = int(get_env_var(LIMIT_ENV_VAR, LIMIT_ENV_VAR_DEFAULT))
        repo_path = get_repo_path(__file__)

        repo = Repo(repo_path)
        stale_branches = get_stale_branches(repo, days, limit)

        # Sort by descending
        stale_branches = sorted(stale_branches, key=lambda x: x.last_committed_date, reverse=True)

        # Filter out protected branches
        stale_branches = [branch for branch in stale_branches if branch.name not in PROTECTED_BRANCHES]

        stale_branches_count = len(stale_branches)
        logger.info(f"Found {stale_branches_count} stale branches")
        logger.debug(f"{stale_branches}")

        if stale_branches:

            logger.info("Authenticating with GitHub...")
            auth = github.Auth.Token(token)

            # TODO remove after debug
            gh_client = github.Github(auth=auth, verify=False)
            logger.info("Finished authenticating with GitHub")

            repo_name = "/".join([owner, repo_name])
            gh_repo = gh_client.get_repo(repo_name)
            logger.info(f"Working on repo {gh_repo}")

            for branch in stale_branches:
                logger.info(f"Deleting '{branch=}'...")

                try:
                    gh_repo.get_git_ref(f"heads/{branch.name}")
                    # ref.delete()
                    branch.deleted = True
                    logger.info(f"{branch=} deleted")
                except github.GithubException as e:
                    logger.error(f"{e.__class__.__name__} attempting to delete '{branch=}'. It was not deleted")
                    branch.deleted = False
                    branch.error = e

        write_deleted_summary_to_file(
            header=SUMMARY_HEADER.format(count=stale_branches_count, days_ago=days),
            table_headers=SUMMARY_TABLE_HEADERS,
            table_rows=[[branch.name, branch.get_last_committed_date(), branch.deleted, branch.error]
                        for branch in stale_branches]
        )

    except Exception as e:
        logger.exception(f"{e.__class__.__name__}: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
