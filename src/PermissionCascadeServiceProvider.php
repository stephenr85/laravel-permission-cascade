<?php

namespace Rushing\PermissionCascade;

use Illuminate\Support\ServiceProvider;
use Rushing\PermissionCascade\Contracts\CredentialScopeResolver;
use Rushing\PermissionCascade\Contracts\EntitlementResolver;
use Rushing\PermissionCascade\Contracts\ReachResolver;
use Rushing\PermissionCascade\Support\DefaultReachResolver;
use Rushing\PermissionCascade\Support\NullCredentialScopeResolver;
use Rushing\PermissionCascade\Support\NullEntitlementResolver;
use Rushing\PermissionCascade\Support\PermissionNamer;

class PermissionCascadeServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__.'/../config/permission-cascade.php', 'permission-cascade');

        $this->app->singleton(PermissionNamer::class, fn () => new PermissionNamer);

        // The credential-scope seam. Defaults to unscoped (NullCredentialScopeResolver),
        // so authorization is unchanged until a host binds a narrowing resolver — either
        // by pointing config('permission-cascade.credential_scope_resolver') at a class or
        // closure, or by rebinding this contract directly (e.g. an accounts package that
        // sources the scope from an acting API token). The cascade never learns what the
        // credential mechanism is; it only consults permission-names.
        $this->app->singleton(CredentialScopeResolver::class, function ($app) {
            $resolver = config('permission-cascade.credential_scope_resolver');

            if ($resolver === null) {
                return new NullCredentialScopeResolver;
            }

            return is_callable($resolver) ? $resolver($app) : $app->make($resolver);
        });

        // The reach seam (see Contracts\ReachResolver). Defaults to DefaultReachResolver,
        // which reproduces the historical tenant/platform vocabulary with no anonymous
        // reach — so authorization is unchanged until a host binds a resolver that adds
        // tiers (e.g. a public-to-anonymous tier). A host points
        // config('permission-cascade.reach_resolver') at a class or closure, or rebinds
        // this contract directly.
        $this->app->singleton(ReachResolver::class, function ($app) {
            $resolver = config('permission-cascade.reach_resolver');

            if ($resolver === null) {
                return new DefaultReachResolver;
            }

            return is_callable($resolver) ? $resolver($app) : $app->make($resolver);
        });

        // The entitlement seam (see Contracts\EntitlementResolver) — the feature-access axis,
        // distinct from the per-action cascade. null → NullEntitlementResolver: every principal
        // holds the empty set, so an unbound host is entitled to nothing and behaviour is
        // unchanged (the DefaultReachResolver discipline, ADR-0009). Point this at a class-string
        // or a closure returning an EntitlementResolver to map a plan/grant model to a flat set of
        // entitlement keys (plan-baseline ∪ grants − denies). beam is the authority that binds the
        // concrete resolver + registers entitlement gate abilities (Frame OS ADR-0013). Hosts may
        // instead rebind the contract in the container directly.
        $this->app->singleton(EntitlementResolver::class, function ($app) {
            $resolver = config('permission-cascade.entitlement_resolver');

            if ($resolver === null) {
                return new NullEntitlementResolver;
            }

            return is_callable($resolver) ? $resolver($app) : $app->make($resolver);
        });
    }

    public function boot(): void
    {
        if ($this->app->runningInConsole()) {
            $this->publishes([
                __DIR__.'/../config/permission-cascade.php' => $this->app->configPath('permission-cascade.php'),
            ], 'permission-cascade-config');
        }

        $this->configureSpatieTeams();
    }

    /**
     * The cascade is teams-first. Unless the host opts out
     * (`permission-cascade.manage_spatie_teams` => false, as ~/Herd/audiostud, ~/Herd/thingsontv
     * and ~/Herd/standwell do), force spatie into teams-mode with the configured foreign key.
     *
     * ⚠️ Forcing is only a DEFECT where the host cannot satisfy it, and the estate was swept for
     * that on 2026-09-03 rather than assumed. Fifteen roots install this package (resolved with
     * `pwd -P`; three of them — beam/satellite/tower — are Herd symlinks onto starters, and
     * beam-pilot-gcp-cloud-run vendors a frozen copy that carries this method all the same).
     * Three opt out; twelve resolve `config('permission.teams') === true` at runtime, asked of the
     * booted container rather than read off `config/permission-cascade.php` — the flagship's copy
     * of that file omits the key entirely and so takes this default deliberately.
     *
     * **None of the twelve is broken.** The discriminator is the live pivot, not the migration:
     *   - eight have `model_has_roles.team_id` NULLABLE (the beam-accounts stub), so a team-less
     *     `assignRole()` writes NULL and reads back — probed in a rolled-back transaction at
     *     beam, satellite, tower, schemastud, splicewire, splicewire-app (central and three tenant
     *     schemas);
     *   - fable and numero have it NOT NULL (spatie's own stub under `key_type => 'int'`). A
     *     team-less assign there DOES fail — but neither host has a team-less path: every
     *     assignment goes through beam-accounts' `TeamProvisioner`/`TeamMembers`, which set the
     *     registrar's team id first. Proven by running each host's own
     *     `CreatesNewUsers` action in a rolled-back transaction: numero provisions team 4 and
     *     writes `team_id`, fable assigns no role at all. Both are teams hosts by intent;
     *   - calcucrypt, entreport, stephenrushing and beam-pilot-gcp-cloud-run have NO permission
     *     tables and no permission migration to run, so the forced config key is inert there.
     *     (entreport and stephenrushing are broken by an unrelated users-table drift —
     *     satellite-runbook mobile-responsive-sweep 11 — not by this.)
     *
     * The failure this forcing produces, when it produces one, is `Unknown column
     * 'model_has_roles.team_id'` (schema created while teams was off) or `Column 'team_id' cannot
     * be null` (created after, never populated). Both present as anything but a config problem.
     *
     * ⚠️ The seam is the VALUE the column holds, not the column name. Measured 2026-08-29
     * across every root that installs spatie: the column is `team_id` at all of them, the
     * platform included — what differs is that a tenanted host stores the TENANT key in it.
     * This docblock used to say "'tenant_id' on the platform", and that sentence was the source
     * of a fossil that had propagated into the flagship's published `config/permission.php` and
     * into a beam-accounts docblock. beam-facade 168.
     */
    protected function configureSpatieTeams(): void
    {
        if (! config('permission-cascade.manage_spatie_teams', true)) {
            return;
        }

        // spatie reads the key from column_names.team_foreign_key (the registrar's
        // teamsKey and the migration both use it) — not a top-level permission key.
        config([
            'permission.teams' => true,
            'permission.column_names.team_foreign_key' => config('permission-cascade.team_foreign_key', 'team_id'),
        ]);
    }
}
