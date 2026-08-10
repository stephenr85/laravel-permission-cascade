> You are in **rushing/laravel-permission-cascade** — host-agnostic authorization cascade for Laravel: model-scoped permission naming, a base policy resolving `Model.action -> Model.{id}.action -> Model.own.action` ownership, and spatie teams-mode conventions with a configurable team foreign key.

This is a leaf Laravel package. `BaseModelPolicy` resolves abilities through four rungs
(class, instance, steward/owner, shared ACL via `HasVisibility`), and `HasVisibility` models
two orthogonal axes (reach + grant ledger) on top of spatie/laravel-permission's teams mode.
