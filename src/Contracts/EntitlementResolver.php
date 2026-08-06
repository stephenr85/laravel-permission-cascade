<?php

namespace Rushing\PermissionCascade\Contracts;

use Rushing\PermissionCascade\Support\NullEntitlementResolver;

/**
 * The entitlement seam — the *feature-access* axis, distinct from the per-action permission
 * cascade (Frame OS ADR-0013 §3).
 *
 * Where {@see ReachResolver} answers "how broad is a record's audience" and the cascade answers
 * "may this principal perform this action on this subject", **entitlement** answers a third,
 * orthogonal question: *which feature bundles does this principal hold?* — the plan/tenant-held
 * source that gates monetized capabilities (`own-a-song`, `workbench.enter`, a metered remote
 * capability) independent of any subject.
 *
 * A host binds one implementation (via `config('permission-cascade.entitlement_resolver')` or by
 * rebinding this contract) mapping its own plan/grant logic to a flat set of entitlement keys —
 * canonically `plan-baseline ∪ grants − denies`. The package ships a {@see NullEntitlementResolver}
 * that returns the empty set, so an unbound host holds no entitlements and its behaviour stays
 * byte-for-byte until it binds — the `DefaultReachResolver` discipline (ADR-0009).
 *
 * The **principal** is deliberately untyped: two principals ask this seam — a user (host in-request)
 * and a tenant/credential (satellite connector pre-flight). The resolver knows which principal shape
 * it was bound for; the kernel only unions the returned key set into the Gate.
 */
interface EntitlementResolver
{
    /**
     * The set of entitlement keys `$principal` holds. A *set*: the returned list is deduplicated
     * and order-insensitive. An empty array means "holds no entitlements" (the null default).
     *
     * @param  mixed  $principal  The user, tenant, or credential principal this seam was bound for.
     * @return array<int, string> The held entitlement keys (deduped).
     */
    public function entitlementsFor(mixed $principal): array;
}
