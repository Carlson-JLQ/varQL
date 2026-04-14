# VarQL

`VarQL` is the new research codebase for variant-aware CodeQL query synthesis.

It is developed alongside the `QLCoder` baseline:

- `QLCoder` remains the baseline implementation and comparison target
- `VarQL` is the new method under development

## Current Scope

The repository is being initialized in phases:

1. scaffold the new project structure
2. port benchmark loading and evaluation
3. introduce schema IR
4. add seen/held-out variant split
5. implement variant-aware synthesis

## Naming

- Task: `Patch-to-Variant Query Synthesis`
- System: `VarQL`
- Baseline: `QLCoder`

## Layout

```text
varQL/
  README.md
  VARQL_PROJECT_PLAN.md
  pyproject.toml
  src/varql/
  tests/
  paper/
  configs/
  benchmarks/
  scripts/
```
