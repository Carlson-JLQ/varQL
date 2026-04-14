# VarQL Project Plan

## 1. Project Positioning

`VarQL` is the new research project built on top of the lessons learned from the `QLCoder` baseline.

The role split should stay clear:

- `qlcoder/` remains the **baseline implementation** and the **comparison target**
- `varQL/` becomes the **main research codebase** for the new method

This separation is important for:

- clean baseline reproduction
- controlled comparison experiments
- artifact packaging
- avoiding confusion between baseline patches and new-method contributions

## 2. Research Goal

The core goal of `VarQL` is:

- move from **seed-level query recovery** to **variant-aware query synthesis**

More concretely, the system should not only synthesize a CodeQL query that separates one seed CVE's vulnerable and fixed versions, but also produce a query that generalizes to related variants in the same vulnerability family.

## 3. Main Hypothesis

The pilot baseline suggests that the main failure mode is not query compilation or seed discrimination, but lack of abstraction. Therefore, `VarQL` should focus on three design changes:

1. `variant-aware objective`
   query synthesis should optimize for family-level behavior, not only seed-level vuln/fix discrimination

2. `schema IR`
   the system should synthesize queries from a structured vulnerability schema rather than directly from raw diff text

3. `generalization-oriented evaluation`
   experiments should distinguish:
   - seed success
   - seen-variant success
   - held-out test-variant success

## 4. System Vision

The intended `VarQL` pipeline is:

1. input a seed CVE and associated patch/diff
2. run semantic analysis and AST/diff analysis
3. extract an instance-level `schema IR`
4. optionally align multiple seen schemas into a family-level schema
5. synthesize a CodeQL query from the schema
6. evaluate on:
   - seed pair
   - seen variants
   - held-out variants
7. use seen-variant feedback for refinement
8. report held-out performance as the real generalization metric

## 5. Relationship to QLCoder

`VarQL` should reuse only what is still useful from `QLCoder`:

- CodeQL execution wrappers
- database preparation logic
- AST extraction logic
- basic agent backend support
- benchmark assets and manifests
- evaluation utilities when they are general enough

`VarQL` should not inherit the seed-only optimization logic as-is. That logic is the main bottleneck exposed by the pilot baseline.

## 6. Recommended Repository Structure

Suggested structure for `varQL/`:

```text
varQL/
  README.md
  VARQL_PROJECT_PLAN.md
  pyproject.toml
  paper/
  configs/
  benchmarks/
  scripts/
  src/
    varql/
      __init__.py
      config.py
      schema_ir.py
      schema_extraction.py
      family_schema.py
      synthesis/
      evaluation/
      benchmark/
      agents/
      codeql/
  tests/
```

Suggested internal breakdown:

- `src/varql/schema_ir.py`
  schema IR data structures and validation
- `src/varql/schema_extraction.py`
  build schema IR from seed patch, Phase 1 summaries, and Phase 2 AST output
- `src/varql/family_schema.py`
  merge or align multiple seen schemas into a family schema
- `src/varql/synthesis/`
  query synthesis logic
- `src/varql/evaluation/`
  seed / seen / held-out evaluation logic
- `src/varql/benchmark/`
  benchmark loading and split definitions
- `src/varql/agents/`
  Claude/Codex backend integration for the new method

## 7. Development Phases

### Phase 0: Scaffold the New Repo

Goal:

- create a clean, minimal project skeleton
- establish naming, config, and module boundaries

Deliverables:

- package skeleton under `src/varql/`
- basic `README.md`
- benchmark path config
- test harness

### Phase 1: Reproduce the Pilot Benchmark in VarQL

Goal:

- make `VarQL` able to load the existing pilot benchmark and run seed-centered evaluation without yet changing the core method

Deliverables:

- benchmark loader
- support for pilot manifest
- support for seed / positive variant / hard negative execution
- result schema compatible with baseline comparison

Why this matters:

- it gives the new repo a working experimental spine before method changes begin

### Phase 2: Introduce Schema IR

Goal:

- formalize the vulnerability representation used by the system

Deliverables:

- `schema_ir.py`
- JSON-serializable schema format
- instance-level schema extraction for at least one family
- example schemas for pilot seeds

Minimum schema fields:

- `schema_id`
- `family_id`
- `summary`
- `sources`
- `sinks`
- `sanitizers`
- `guards`
- `propagations`
- `patch_semantics`
- `query_constraints`

### Phase 3: Add Seen/Test Variant Split

Goal:

- avoid using the same variants for both refinement and final evaluation

Deliverables:

- split protocol for each seed-centered family case
- explicit `seen_variants`
- explicit `held_out_variants`
- reporting for:
  - seed success
  - seen-variant recall
  - held-out variant recall

This phase is necessary before any paper-grade claim about generalization.

### Phase 4: Variant-Aware Refinement

Goal:

- allow the agent to refine queries using the seed and seen variants
- keep held-out variants fully hidden until final evaluation

Deliverables:

- refinement-time evaluation on:
  - seed vuln/fix
  - seen variants
  - hard negatives
- generalized feedback categories such as:
  - seed-only overfit
  - missed source modeling
  - missed sink modeling
  - missing guard/sanitizer abstraction
  - over-broad query

### Phase 5: Family-Level Abstraction

Goal:

- move beyond instance-level schema extraction toward family-level synthesis

Deliverables:

- schema alignment across seen variants
- family schema construction
- synthesis prompts or templates that consume family schema instead of raw patch text

### Phase 6: Main Experiments

Goal:

- compare `QLCoder` and `VarQL` under a clean protocol

Main comparisons:

- seed success
- seen-variant recall
- held-out variant recall
- negative FP rate
- compile rate
- iteration count
- token and dollar cost

## 8. Immediate Implementation Priorities

The best near-term order is:

1. scaffold the `varQL` repository
2. copy or re-implement benchmark loading from `qlcoder`
3. define the schema IR in code
4. support a benchmark split:
   - seed
   - seen variants
   - held-out variants
5. run the baseline protocol inside `varQL`
6. only then begin variant-aware synthesis changes

This order keeps the repo scientifically grounded and avoids building method code before the evaluation protocol is stable.

## 9. What Should Be Measured From Day One

Every run in `VarQL` should aim to report:

- `seed_success`
- `seen_variant_recall`
- `held_out_variant_recall`
- `negative_fp_rate`
- `compile_success`
- `iteration_count`
- `token_cost`
- `wall_clock_time`

If these are not recorded from the start, later comparisons will be much harder.

## 10. Suggested First Milestone

The first milestone for `VarQL` should be:

- load the current pilot benchmark
- define a minimal schema IR
- run one seed through:
  - schema extraction
  - baseline query generation
  - seed / seen / held-out evaluation

Completion criterion:

- `VarQL` can execute one full experimental path without depending on the old `QLCoder` orchestration scripts

## 11. Suggested Naming in the Paper

Use the following naming convention consistently:

- **Task**: `Patch-to-Variant Query Synthesis`
- **System**: `VarQL`
- **Baseline**: `QLCoder`

This gives a clean narrative:

- `QLCoder` is the seed-discrimination baseline
- `VarQL` is the variant-aware extension

## 12. Near-Term Risks

The main risks to manage early are:

- mixing baseline and new-method logic in ways that weaken comparison clarity
- letting seen-variant optimization leak into held-out evaluation
- over-engineering the schema IR before a minimal version is working
- spending too much time on prompt details before the split protocol is finalized

## 13. Practical Next Step

The next concrete step should be:

- create the initial `VarQL` code skeleton
- then port benchmark loading and evaluation first

In short: build the evaluation spine before the new synthesis method.
