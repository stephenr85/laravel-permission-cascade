<?php

use Rushing\PermissionCascade\Contracts\EntitlementResolver;
use Rushing\PermissionCascade\Support\NullEntitlementResolver;
use Rushing\PermissionCascade\Tests\Fixtures\User;

/**
 * The entitlement seam (Frame OS ADR-0013 §3): a host binds one resolver mapping a principal to a
 * flat set of entitlement keys; unbound → the null default holds nothing, keeping existing hosts
 * byte-for-byte unchanged (the DefaultReachResolver discipline, ADR-0009).
 */
it('resolves to the empty set when no resolver is bound (the null default)', function () {
    // Nothing binds config('permission-cascade.entitlement_resolver'), so the provider resolves
    // NullEntitlementResolver → every principal holds nothing.
    $resolver = app(EntitlementResolver::class);

    expect($resolver)->toBeInstanceOf(NullEntitlementResolver::class);
    expect($resolver->entitlementsFor(null))->toBe([]);
    expect($resolver->entitlementsFor(new User(['name' => 'A', 'email' => 'a@example.test'])))->toBe([]);
});

it('binds a host resolver via config as a class-string', function () {
    config(['permission-cascade.entitlement_resolver' => FakeEntitlementResolver::class]);

    $resolver = app(EntitlementResolver::class);

    expect($resolver)->toBeInstanceOf(FakeEntitlementResolver::class);
});

it('binds a host resolver via config as a closure', function () {
    config(['permission-cascade.entitlement_resolver' => fn () => new FakeEntitlementResolver(['own-a-song'])]);

    expect(app(EntitlementResolver::class)->entitlementsFor(null))->toBe(['own-a-song']);
});

it('lets a host resolver return the plan-baseline ∪ grants − denies set algebra', function () {
    // Model a host that computes plan-baseline ∪ grants − denies and returns the deduped key set.
    $resolver = new FakeEntitlementResolver(
        entitlements: plan_algebra(
            baseline: ['own-a-song', 'go-songwriter'],
            grants: ['workbench.enter', 'own-a-song'], // own-a-song already in baseline → deduped
            denies: ['go-songwriter'],                 // subtracted
        ),
    );

    $held = $resolver->entitlementsFor(null);

    sort($held);
    expect($held)->toBe(['own-a-song', 'workbench.enter']);
});

it('treats the returned list as a set (deduplicated)', function () {
    $resolver = new FakeEntitlementResolver(['a', 'a', 'b', 'b', 'a']);

    $held = $resolver->entitlementsFor(null);
    sort($held);

    expect($held)->toBe(['a', 'b']);
});

/**
 * A fixture host resolver — the shape beam / a host binds. Dedupes its returned set.
 */
class FakeEntitlementResolver implements EntitlementResolver
{
    /** @param array<int, string> $entitlements */
    public function __construct(private array $entitlements = []) {}

    public function entitlementsFor(mixed $principal): array
    {
        return array_values(array_unique($this->entitlements));
    }
}

/**
 * The canonical set algebra a real resolver computes: plan-baseline ∪ grants − denies, deduped.
 *
 * @param array<int, string> $baseline
 * @param array<int, string> $grants
 * @param array<int, string> $denies
 * @return array<int, string>
 */
function plan_algebra(array $baseline, array $grants, array $denies): array
{
    $union = array_unique([...$baseline, ...$grants]);

    return array_values(array_diff($union, $denies));
}
