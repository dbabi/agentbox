# Git and GitHub

**Status:** Built (milestone 5). It has passed its tests in QEMU VMs against a stand-in for GitHub, not against GitHub itself.
Approvals are made on the box by an admin for now. Signed approvals from your laptop come with milestone 6.

The git service, `agentbox-git`, is how agents use git.
Each agent has its own local repos on the box.
A task pushes to them and fetches from them, and never holds a GitHub credential.
A human approves every write to GitHub.

## What a task can do

- Push and fetch its agent's local repos at `http://127.0.0.1:8082/<repo>`, through the task's own socket.
  Another agent's repos don't exist for it: a missing repo and another agent's repo give the same `404`.
- Push only branches under `agent/<name>/`, where `<name>` is its agent.
  A push to `main`, a tag, or another agent's branches is refused.
- Ask for these operations, through the task gate:

| Operation | What it does | Needs |
|---|---|---|
| `repo.create` | Makes a local repo for the agent | Nothing |
| `repo.push` | Pushes a commit that is already in a local repo to an `agent/<name>/` branch of one of the agent's GitHub remotes | A human's approval |
| `gh.pr.create` | Opens a pull request from a pushed `agent/<name>/` branch | A human's approval |
| `gh.pr.comment`, `gh.issue.comment` | Comments on a pull request or an issue | A human's approval |
| `repo.merge` | Merges a commit into a local repo's `main` | A human's approval |

An operation that needs approval waits as a pending operation.
The task gets `NEEDS_SIGNATURE` with the pending id at once, and can go on with other work.

## Set up GitHub access

You need: the box set up, an agent (`agentbox agent add`), and root on the box.
Run the commands below as root on the box. The `agentbox` binary is not on `PATH`, so they give its full path.

1. On GitHub, make a fine-grained personal access token, or a GitHub App installation token, for only the repos you will register.
   Give it contents read and write, pull requests read and write, and issues read and write.
2. On the box, store the token. The command asks for it without showing it, or reads it from standard input, so the token never lands in your shell history.
   rootd encrypts it with `systemd-creds` and restarts `agentbox-git`. Only that service can read the plaintext, from its own memory-only credentials directory.
   ```sh
   sudo /var/lib/agentbox/current/bin/agentbox secret set --name github-token
   ```
3. Let the git service reach GitHub. rootd resolves these names for it, and it can reach no other address.
   ```sh
   sudo /var/lib/agentbox/current/bin/agentbox egress allow --svc git --entry github.com:443
   sudo /var/lib/agentbox/current/bin/agentbox egress allow --svc git --entry api.github.com:443
   ```
4. Register each GitHub repo as a remote of one agent. `--project` names the agent's local repo that pushes to it; agentbox makes it if it is missing.
   agentbox asks GitHub for the repo's id and visibility, and every approval re-checks them.
   ```sh
   sudo /var/lib/agentbox/current/bin/agentbox remote set --id claude-origin --agent claude --project app --url https://github.com/OWNER/REPO
   sudo /var/lib/agentbox/current/bin/agentbox remote list
   ```
5. On GitHub, protect the repo:
   - Add a ruleset that lets the token update only `agent/**` branches.
   - A pushed branch runs its own workflow files. Keep Actions secrets in environments whose deployment branch rule leaves out `agent/**`, or turn Actions off.

## Approve or deny

```sh
sudo /var/lib/agentbox/current/bin/agentbox pending list
sudo /var/lib/agentbox/current/bin/agentbox approve pnd_01...          # shows the operation, asks, then runs it
sudo /var/lib/agentbox/current/bin/agentbox pending deny --id pnd_01...
```

`agentbox approve` shows the bound facts first: the remote, its visibility, the branch and commit.
Then it shows the agent's own text, the pull request title and the comment body, under `untrusted text`.
Every control or non-ASCII character in that text is escaped, so it can't move the cursor or hide a line.
A remote that is not private is flagged.

If an operation shows `executing` and nothing is running it, for example after the git service was down, `agentbox approve` on it looks for the write on GitHub and records what it finds. It never sends the write again.

An ask expires 15 minutes after the task made it.
A task can have 3 asks open at once, and its ask budget (3 by default) counts every ask.

## What the box checks

- **Before a push lands** (the local repos' hook): the branch is under `agent/<name>/`, the push fits the agent's daily cap, and no pushed file, commit or branch name holds the task's canary (below).
  A refusal prints two lines that git shows as `remote:` lines: a sentence, then the details as JSON.
- **Push size:** at most 512 MiB in one push, and 4 GiB per agent per day (UTC). A push over the daily cap is refused before git stores any of it.
  The daily cap is `git.push_bytes_day` in the box's budgets, which `agentbox budget set` replaces. The next push uses the new value.
- **At approval:** the task is still running or finished normally, the remote is unchanged, GitHub still reports the same repo id and visibility, and the bound commit is still in a local branch.
  For a pull request, the branch on GitHub must still be at the commit the task named.
- **Each write runs once.** The git service records every operation it starts and refuses to start one twice.
  Each comment and pull request body ends with a hidden marker, `<!-- agentbox-op:pnd_... -->`.
  If rootd restarts while a write is in flight, it asks the git service to find the write on GitHub by that marker, or the branch by its commit, and records the result. It never sends the write again.
  If nothing is found, the operation becomes `indeterminate`, and a new pending operation with the same marker waits for you.
- **GitHub's own answers stay out of tasks.** A refusal reaches the task as `REMOTE_REJECTED` with a short reason, such as `pr_exists`. GitHub's text goes only to the audit log.

## Taint and git

- A push from a tainted task taints every branch it updates, and the hook records the commits it brings in as tainted.
- A fetch that may deliver a tainted branch taints the fetching task first.
- `repo.merge` carries taint into `main`: merging a tainted branch, or a commit a tainted task pushed, taints `main` before `main` moves.
  Approving the merge doesn't clear that taint.

## The canary

Each task gets a fresh canary: a random value shaped like an Anthropic API key.
It is the task's LLM key slot, its `GITHUB_TOKEN`, and the password in `~/.netrc` and gh's `hosts.yml`.
It is a credential for nothing. The real keys and the GitHub token stay outside the task.

The box looks for the canary where a task's work leaves it: in every pushed object and branch name, and in pull request titles and bodies and comments.
It finds the raw value, the value split across lines or quoted pieces, its base64 at any offset, and its hex.
A hit refuses the request with `EXFIL_CANARY`, taints the task, writes an audit record and sends you an alert.

The keys broker looks for it too, in each model request a task sends: the body and the headers it passes on to the vendor.
A hit there taints the task and alerts you once for that task, but the request still goes to the vendor.
The vendor gets no real credential that way, and refusing would break a task whose conversation merely quotes its own environment.

The hook also runs the credential rules of the workspace scan on every pushed file.
A match alerts you, but the push still lands: only the canary is sure proof of an exfiltration attempt.

## Limits

- Until signed approvals land, an approval is a call on the box by a member of `agentbox-admin`. Anyone who can log in as the admin can approve.
- There is no standing push policy yet, so every `repo.push` asks.
- The canary is a detection aid, not a guarantee. A task can encode it in a way the scan doesn't cover, and tunnels through the proxy are not scanned.
- A canary that a task writes into its workspace looks like a key to the workspace credential scan, which then blocks the agent's next task until you acknowledge it (issue #289).
- In `--encryption none` mode, the key that encrypts the stored token is a file on the same disk, so the encryption only hides the token from a casual look. The [Security Model](Security-Model.md) explains it.

## See also

- [Architecture](Architecture.md#the-git-broker)
- [Security Model](Security-Model.md)
- [Testing and Gates](Testing-and-Gates.md)
