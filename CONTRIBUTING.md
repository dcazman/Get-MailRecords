# Contributing to Get-MailRecords

Thanks for your interest in contributing! This document covers how to report bugs, suggest features, and submit code changes.

---

## Reporting Bugs

Open a [GitHub Issue](https://github.com/dcazman/Get-MailRecords/issues) and include:

- PowerShell version (`$PSVersionTable`)
- Operating system (Windows / Linux / macOS)
- DNS tool in use (`Resolve-DnsName` or `dig`)
- The exact command you ran
- The output or error message you received
- What you expected to happen

---

## Suggesting Features

Open a [GitHub Discussion](https://github.com/dcazman/Get-MailRecords/discussions) or an Issue tagged as a feature request. Describe the use case — what problem it solves and how you'd expect it to work.

---

## Submitting Code

1. **Fork** the repository and create a branch from `main`:

```powershell
git checkout -b feature/your-feature-name
```

2. **Make your changes** — keep them focused. One feature or fix per pull request.

3. **Test on at least one platform** before submitting. If you can test on both Windows and Linux/macOS, even better.

4. **Follow the existing code style:**
   - 4-space indentation
   - Comment non-obvious logic
   - Use full parameter names in internal code (not aliases)
   - Keep helper functions scoped inside `process` unless there's a strong reason not to

5. **Open a Pull Request** against `main` with a clear description of what changed and why.

---

## Testing Checklist

Before submitting, verify your change works for:

- [ ] Basic domain lookup (`GMR -d example.com`)
- [ ] Subdomain flags (`-Sub`, `-JustSub`)
- [ ] DKIM auto-discovery and explicit selector (`-Selector`)
- [ ] All record types (`-RecordType TXT`, `CNAME`, `BOTH`)
- [ ] Pipeline input (`"a.com","b.com" | Get-MailRecords`)
- [ ] Export to CSV and JSON (`-Export`)
- [ ] Windows PowerShell 5.1 and/or PowerShell 7+

---

## What to Avoid

- Don't submit changes that break backward compatibility without discussion first
- Don't add external module dependencies — the module is intentionally dependency-free
- Don't modify the default DKIM selector list without a strong justification

---

## Questions?

Open a [Discussion](https://github.com/dcazman/Get-MailRecords/discussions) — happy to help.
