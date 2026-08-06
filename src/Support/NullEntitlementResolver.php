<?php

namespace Rushing\PermissionCascade\Support;

use Rushing\PermissionCascade\Contracts\EntitlementResolver;

/**
 * The default, unbound entitlement resolver: every principal holds the **empty set**.
 *
 * When nothing binds an entitlement source, no feature is entitled — existing hosts are
 * byte-for-byte unchanged until they bind their plan logic (the `DefaultReachResolver`
 * discipline, ADR-0009). A host binds a real resolver via
 * `config('permission-cascade.entitlement_resolver')` or by rebinding the contract.
 */
class NullEntitlementResolver implements EntitlementResolver
{
    public function entitlementsFor(mixed $principal): array
    {
        return [];
    }
}
