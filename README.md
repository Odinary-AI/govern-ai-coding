# Govern AI Coding

An Agent Skill for keeping complex AI-assisted coding changes aligned with
project facts, decisions, and evidence.

It resolves document authority before edits begin, then binds semantic review,
frozen final content, project validation, and human decisions before work is
called complete.

Every governed workspace declares a root `README.md` as the common navigation
starting point for humans and AI. That navigation role does not implicitly make
README authoritative for product, architecture, work state, release, or
history.

## Install in Codex

```bash
git clone https://github.com/Odinary-AI/govern-ai-coding.git
mkdir -p ~/.codex/skills/govern-ai-coding
cp -R govern-ai-coding/README.md govern-ai-coding/LICENSE \
  govern-ai-coding/SKILL.md govern-ai-coding/agents \
  govern-ai-coding/references govern-ai-coding/scripts \
  ~/.codex/skills/govern-ai-coding/
```

For another Agent Skills-compatible host, use that host's normal installation
method and preserve the destination directory name `govern-ai-coding`.

## Use

Before implementation:

```text
Use $govern-ai-coding to govern this change before implementation begins.
```

Before completion:

```text
Use $govern-ai-coding to close out this change against project facts and evidence.
```

## Requirements

- Python 3.9 or later.
- Git is optional and is used only for Git-backed change inventory.

The Skill does not decide product meaning, architecture meaning, formal
release claims, or irreversible archival choices. Generated findings remain
evidence until written into the project's mapped authority documents.

See [SKILL.md](SKILL.md) for the complete workflow and
[the adapter schema](references/adapter-schema.md) for project integration.

## License

Available under the [MIT License](LICENSE).
