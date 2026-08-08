# Native contract fixtures

These are sanitized, synthetic OpenAPI 2.4 contract fixtures. Numeric sizes and
timestamps demonstrate schema shape; they are not canary measurements or runtime
defaults. Evidence-backed OCI facts and implementation gates live in the OCI
behavior appendix.

The paired fixtures cover both the normal wire shape and the M1 degradation
shapes: capacity rejection input, expired projection, killed/indeterminate
runner observations, indeterminate capture, eviction, hard deadline, bounded
log truncation, and a closed launcher-mediated terminal. They contain no live
credential or cluster identity.
