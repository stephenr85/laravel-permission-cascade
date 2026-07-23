<?php

namespace Rushing\PermissionCascade\Contracts;

/**
 * The credential-scope seam.
 *
 * A host binds an implementation to narrow a principal's authority by an *optional*
 * credential-scope — a set of permission-names the acting credential is allowed to
 * exercise. The cascade consults this at every authorization decision:
 *
 *   effective authority = principal permissions ∩ credential-scope
 *
 * The seam names permissions only; it knows nothing about tokens, Sanctum, or any
 * credential mechanism (ADR-0055 stays intact). The host (e.g. an accounts package)
 * supplies the mechanism-specific implementation.
 */
interface CredentialScopeResolver
{
    /**
     * Resolve the acting credential's scope.
     *
     * @return array<int, string>|null null → unscoped (authorize exactly as the
     *                                 principal); an array of permission-names → the
     *                                 acting credential may exercise only those.
     */
    public function resolve(): ?array;
}
