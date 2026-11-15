# Frozen Superset component evaluation

This is evaluator-only material, not agent retrieval input. It tests a known
historical reference change and does not measure independent AI reproduction.

Source: Apache Superset, Apache License 2.0. The copied source/test files retain
their original Apache license notices. Original source and test helpers are from
commit `463c58cef1a48df974dcab710a868617b58dcb93`; the reference component and
appended regression test come from commit
`b2d19688971c132ed63433f7f823e0c18562e341` (PR #45827), associated with issue #45825.

- https://github.com/apache/superset/issues/45825
- https://github.com/apache/superset/pull/45827
- https://github.com/apache/superset/blob/463c58cef1a48df974dcab710a868617b58dcb93/LICENSE.txt

`oracle.test.tsx` preserves the complete baseline DashboardPage test suite and
appends the upstream regression. Both states run that identical protected file.
Only the DashboardPage runtime file is replaced for the reference run; the wider
Explore change in the upstream PR is outside this proof. API calls and child
components mocked by that existing suite remain mocked. This is a component
regression test, not the full Superset browser navigation/data/backend flow.
