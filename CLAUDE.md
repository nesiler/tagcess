@AGENTS.md

## Claude Code specifics
- Skills and agents are shared with Codex and OpenCode: `.claude/skills` and `.claude/agents` are symlinks to
  `.agents/`. Invoke skills as `/coordinator`, `/issue 42`, `/review 57`, `/adr`. Run reviewer agents with the
  Agent tool (`subagent_type: code-reviewer`, ...).
- Use plan mode for any change that touches more than one file.
- Hooks (`.claude/settings.json`):
  - gofmt/goimports runs after every edit.
  - The Stop gate runs `make check-fast` when Go or agent files changed.
  - A Bash guard blocks write-like commands against the production hosts listed in
    `$HOME/.config/tagcess/guard-patterns.txt`. The guard is a safety net; hard rule 1 still applies.
- After editing anything in `.agents/agents/`, run `make agents`.
