<?php

namespace Rushing\PermissionCascade\Contracts;

/**
 * A policy that names its own decisions for a scoped credential (fleet ADR 0006, rule 1: "each package names its own
 * decisions").
 *
 * Under a scoped credential every Gate decision must resolve to a name the token carries
 * ({@see \Rushing\PermissionCascade\Authorization\CredentialScopeGate}). By default a policy verb on a model is named by
 * the cascade's derivation, `{model}.{verb}` and `{model}.{id}.{verb}`. A policy implements this when one of its
 * decisions is better named otherwise: `BaseModelPolicy` adds its own rungs (`{model}.own.{action}`,
 * `{model}.shared.{action}`) and maps `viewAny` to `{model}.view`; a policy whose verb is the exercise of a flat
 * permission can name that permission.
 *
 * The answer only says which names ADMIT the decision. It never grants: the principal check (the policy itself) still
 * runs after a carried name admits it.
 */
interface NamesDecisions
{
    /**
     * The names that admit `$ability` for a scoped credential, or null to leave it to the cascade's derivation. An empty
     * list means the decision has no name: a scoped credential is refused.
     *
     * @param  array<int, mixed>  $arguments  the check's arguments, subject first
     * @return list<string>|null
     */
    public function decisionNames(string $ability, array $arguments): ?array;
}
