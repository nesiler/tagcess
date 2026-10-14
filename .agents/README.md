# Agent development system

`.agents/` is the single source. Claude Code, Codex and OpenCode use the same skill and agent definitions.
The process they serve is described in `docs/development.md`.

```
AGENTS.md                 Rules for every agent (Codex reads it directly)
CLAUDE.md                 @AGENTS.md + Claude-specific notes
.agents/
  skills/<name>/SKILL.md  Skills: coordinator, issue, review, adr, stack-notes
  agents/<name>.md        Reviewer and researcher definitions (single source)
  templates/adr.md        ADR template
  roles.conf              Default model profile per role, and the reviewer per writer
  coord/                  Child-session protocol and the repo part of the profiles
  agent-kit/kit.conf      agent-kit settings (task source: GitHub issues)
.claude/
  skills -> ../.agents/skills   (symlink)
  agents -> ../.agents/agents   (symlink; frontmatter in Claude format)
  settings.json                 hooks
.codex/agents/*.toml      GENERATED from .agents/agents (make agents). Do not edit
.opencode/agent/*.md      GENERATED from .agents/agents (make agents). Do not edit
scripts/coord/            Coordinator wrapper (coord.sh), tell/hook scripts, coordinator test
scripts/agent-kit/ak      agent-kit dispatcher (vendored)
.github/                  Issue forms, PR template, label set
```

## Everyday use
| Request | Claude Code | Codex / OpenCode |
|---|---|---|
| Plan a milestone, run issues, merge | `/coordinator` | "use the coordinator skill" |
| Work an issue | `/issue 42` | "use the issue skill for #42" |
| Review a PR | `/review 57` | "use the review skill for PR #57" |
| Record a decision | `/adr` | "use the adr skill" |

## Safety nets
- **Claude hooks:** gofmt/goimports on edited Go files; `make check-fast` at Stop (a red gate blocks the turn once,
  the second attempt passes so the agent can explain); a Bash guard that blocks write-like commands against the
  hosts in `$HOME/.config/tagcess/guard-patterns.txt`.
- **Codex:** reviewers run with `sandbox_mode = read-only`. **OpenCode:** reviewer subagents have `edit: deny`.
- **Everyone:** the `make check` gate locally and in CI, and the role rules in `AGENTS.md`.

## Extending
- **New skill:** add `.agents/skills/<name>/SKILL.md`. Frontmatter: only `name` and `description`; the description
  says when to use it.
- **New agent:** add `.agents/agents/<name>.md` with frontmatter `name`, `description`, `tools`, `model` (Claude)
  and `codex_sandbox`, then run `make agents`.
- **Rules:** for every line ask "would an agent make a mistake without it?" If not, leave it out. Rarely needed
  knowledge goes into a skill; a rule that must hold goes into a hook or `make check`.
