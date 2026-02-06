# Curated Skills Marketplace

A curated, community-vetted Claude Code plugin marketplace. Every skill here has been reviewed for quality and safety before inclusion.

## Why Curated?

The Claude Code skills ecosystem is growing fast, but not everything out there is trustworthy. Some published skills have been found to contain backdoors or malicious hooks. This repo exists as a **gate**—a place where the community can submit skills they use and trust, with review and CI checks enforcing quality and safety standards.

If you're using a skill from the wild, consider submitting it here so others can benefit from reviewed, vetted versions.

## Installation

### Add the Marketplace

```
/plugin marketplace add trailofbits/skills-curated
```

### Browse and Install Plugins

```
/plugin menu
```

### Local Development

To add the marketplace locally (e.g., for testing or development), navigate to the **parent directory** of this repository:

```
cd /path/to/parent  # e.g., if repo is at ~/projects/skills-curated, be in ~/projects
/plugins marketplace add ./skills-curated
```

## Available Plugins

### Development

| Plugin | Description |
|--------|-------------|
| [ask-questions-if-underspecified](plugins/ask-questions-if-underspecified/) | Clarify requirements before implementing |

## Trophy Case

Bugs discovered using curated skills. Found something? [Let us know!](https://github.com/trailofbits/skills-curated/issues/new?template=trophy-case.yml)

When reporting bugs you've found, feel free to mention:
> Found using [Curated Skills](https://github.com/trailofbits/skills-curated)

| Skill | Bug |
|-------|-----|

## Contributing

We welcome contributions! Please see [CLAUDE.md](CLAUDE.md) for skill authoring guidelines.

Every submission goes through code review. We check for:
- Malicious hooks, scripts, or commands
- Quality and completeness (frontmatter, required sections, examples)
- Genuine value-add over Claude's built-in capabilities

## License

This work is licensed under a [Creative Commons Attribution-ShareAlike 4.0 International License](https://creativecommons.org/licenses/by-sa/4.0/).
