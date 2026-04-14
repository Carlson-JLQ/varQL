# Pilot Benchmark Protocol

## 1. Purpose

The `VarQL` pilot benchmark is designed to measure whether a synthesized CodeQL query can:

- recover the original seed vulnerability,
- transfer to related vulnerability variants,
- avoid firing on closely related but semantically different negatives.

The benchmark is therefore **family-centered**, not just **seed-centered**.  
Each evaluation unit is a *seed-centered family case* rather than a single CVE.

## 2. Core Benchmark Unit

Each benchmark case is defined by:

- one `seed CVE`,
- a set of `positive_variants`,
- a set of `hard_negatives`.

This means the system is not only asked:

- "Can the query distinguish the seed vulnerable version from the seed fixed version?"

It is also asked:

- "Can the same query transfer to related variants?"
- "Can it stay specific enough to avoid hard negatives?"

## 3. Roles Inside a Seed-Centered Case

### 3.1 Seed

The `seed` is the primary synthesis target.  
The system receives the seed patch, seed vulnerable database, and seed fixed database.

A successful query should:

- hit the seed vulnerable database,
- avoid the seed fixed database.

### 3.2 Positive Variants

`positive_variants` are vulnerabilities from the same family that should also be detected by a good generalized query.

They are used to measure whether the query captures a reusable family-level pattern instead of a seed-only signature.

For each positive variant, the ideal behavior is:

- hit the vulnerable version,
- avoid the fixed version.

### 3.3 Hard Negatives

`hard_negatives` are samples that are intentionally close to the seed but should **not** be matched by the synthesized query.

These may be:

- same-repository but different-family bugs,
- same API surface but safe code,
- semantically different vulnerabilities that are easy to overfit into.

For each hard negative, the ideal behavior is:

- avoid the vulnerable version,
- avoid the fixed version.

## 4. Why a Seen/Held-Out Split Is Needed

If all positive variants are shown to the agent during refinement and then reused as the final evaluation target, the benchmark becomes much weaker as evidence of generalization.

In that setup, a system might simply adapt to the observed variants rather than learn a transferable vulnerability pattern.

To avoid that problem, the pilot benchmark splits positive variants into:

- `seen_variants`
- `held_out_variants`

This gives the benchmark two distinct roles:

- some variants can be used to shape synthesis,
- others remain hidden until final evaluation.

## 5. Split Design

### 5.1 Current Default Strategy

The current `VarQL` implementation uses a deterministic split rule inside each seed-centered case:

1. Prefer one `same_repo` positive variant as the `seen` refinement variant.
2. If no `same_repo` variant exists, use the first positive variant as `seen`.
3. Put all remaining positive variants into `held_out`.

This logic is implemented in:

- [pilot.py](/root/varQL/src/varql/benchmark/pilot.py)

and exposed through:

- `VariantSeedCase.split_variants()`
- `VariantSeedCase.split_summary()`

### 5.2 Split Semantics

The meaning of the split is:

- `seed`
  The primary synthesis target.
- `seen_variants`
  Variants that may be visible during refinement or family abstraction.
- `held_out_variants`
  Variants that remain hidden during synthesis and are used only for final generalization testing.
- `hard_negatives`
  Always used to test whether the query is too broad.

This yields a four-part evaluation protocol:

- seed recovery
- seen-variant adaptation
- held-out variant generalization
- hard-negative specificity

## 6. Example: JSPWiki XSS Family

For the seed `CVE-2019-10077`, the pilot benchmark currently defines the following case:

- `seed = CVE-2019-10077`
- `positive_variants = [CVE-2019-10078, CVE-2019-10076]`
- `hard_negatives = [CVE-2019-0225]`

Under the current split strategy, this becomes:

- `seed = CVE-2019-10077`
- `seen_variants = [CVE-2019-10078]`
- `held_out_variants = [CVE-2019-10076]`
- `hard_negatives = [CVE-2019-0225]`

The interpretation is:

- the system may use `CVE-2019-10077` and `CVE-2019-10078` during synthesis,
- it must generalize to `CVE-2019-10076` without having seen it during refinement,
- it must not fire on `CVE-2019-0225`.

## 7. Evaluation Expectations

For a seed-centered case, the desired query behavior is:

### 7.1 Seed

- `DB_vul(seed)` should be matched
- `DB_fix(seed)` should not be matched

### 7.2 Seen Variants

- `DB_vul(seen)` should be matched
- `DB_fix(seen)` should not be matched

These variants may influence refinement, so they should be interpreted as *development-time supervision* rather than independent final evidence.

### 7.3 Held-Out Variants

- `DB_vul(held_out)` should be matched
- `DB_fix(held_out)` should not be matched

This is the real test of variant-level generalization.

### 7.4 Hard Negatives

- `DB_vul(negative)` should not be matched
- `DB_fix(negative)` should not be matched

This checks whether the learned pattern is too broad.

## 8. What the Current Pilot Benchmark Measures

With this protocol, the pilot benchmark can distinguish three increasingly strong capabilities:

1. `Seed recovery`
   The system can reproduce the original seed vulnerability.

2. `Seen-variant adaptation`
   The system can use visible family examples to move beyond a seed-only query.

3. `Held-out generalization`
   The system can transfer to unseen variants that were not available during refinement.

This makes the benchmark diagnostically useful.  
For example:

- strong seed success + weak seen recall
  suggests the method is still seed-only,
- strong seen recall + weak held-out recall
  suggests the method adapts to visible variants but does not truly generalize,
- strong held-out recall
  is evidence that the method captures a reusable family pattern.

## 9. Current Strengths and Limitations

### Strengths

- simple and deterministic split,
- easy to reproduce,
- suitable for rapid method iteration,
- already strong enough to reveal the baseline generalization gap.

### Limitations

- many current splits are still same-repository,
- held-out variants are not yet always cross-project,
- the pilot benchmark is still a research prototype rather than the final paper-scale protocol.

## 10. Intended Next-Step Upgrade

For a stronger final benchmark, the preferred direction is:

- `seen_variants = same-repo sibling variants`
- `held_out_variants = cross-repo sibling variants`

That future upgrade would make held-out performance a much stronger measure of true vulnerability-family generalization.

## 11. One-Sentence Summary

The current `VarQL` pilot benchmark is a seed-centered family benchmark in which positive variants are split into:

- `seen_variants`, which may guide synthesis,
- `held_out_variants`, which remain hidden until final evaluation,

while `hard_negatives` continuously test whether the synthesized query has become too broad.



直接跑一个真实 seed吧，使用claude code，直接使用本地配置，不需要输入api-key,然后评估，对比：

baseline raw-diff prompt
VarQL schema-guided prompt
看 seed / seen / held_out 三层指标有没有开始分化。