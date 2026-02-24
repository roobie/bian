# Chronicles

Use [./TEMPLATE.md](./TEMPLATE.md)!

## Usage Guide

**Quick Log** – Use for:
- Minor bug fixes
- Simple feature additions
- Dependency updates
- Refactoring that doesn't change behavior

**Standard Chronicle** – Use for:
- Feature development spanning multiple files
- Bug fixes requiring investigation
- API integrations
- Configuration changes with implications

**Deep Dive** – Use for:
- Architecture decisions
- Performance optimization work
- Complex algorithm implementation
- Major refactoring
- Debugging sessions that revealed important insights
- Anything you'll need to explain to others (or yourself in 6 months)

---

## Pro Tips

**For your coding agent**, try these specific prompts:

- `"Create a quick-log chronicle for this session"`
- `"Chronicle this as a standard session—we made several key decisions"`
- `"Deep-dive chronicle needed—document the algorithm we chose and why"`

**Make it scannable**: Future-you should be able to skim the frontmatter and Quick Summary in **10 seconds** and decide if they need to read more.

**Link chronicles together**: Reference previous chronicle dates when building on earlier work: `"Continues from 2026-02-20 session on auth refactor"`

**Version control**: Commit chronicles with the code they document, or immediately after. They're most valuable when tied to specific commits.
