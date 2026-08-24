# GitHub Setup Checklist

After creating the repository on GitHub (initially **private**):

## Repository Creation

- [ ] Repository visibility: **Private**
- [ ] Default branch: `main`
- [ ] Do **not** initialize with README/.gitignore/license from GitHub
- [ ] License remains unset until owner decision

## Connect the Local Repository

```bash
git remote add origin <REPOSITORY_URL>
git push -u origin main
git push origin --tags
```

(Do not run these until you have created the repository and decided to publish.)

## Branch Protection (`main`)

- [ ] Require pull request before merging
- [ ] Require status checks: `tests` workflow
- [ ] Block force pushes and deletions

## Security and Automation

- [ ] Dependabot enabled (pip + GitHub Actions, monthly — configured in `.github/dependabot.yml`)
- [ ] Secret scanning enabled (and push protection if available)
- [ ] Actions permissions: read repository contents only (workflow already declares `permissions: contents: read`)
