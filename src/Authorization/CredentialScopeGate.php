<?php

namespace Rushing\PermissionCascade\Authorization;

use Closure;
use Illuminate\Auth\Access\Gate as LaravelGate;
use Illuminate\Auth\AuthManager;
use Illuminate\Contracts\Auth\Access\Gate;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Str;
use Rushing\PermissionCascade\Contracts\CredentialScopeResolver;
use Rushing\PermissionCascade\Contracts\NamesDecisions;
use Rushing\PermissionCascade\Facades\PermissionNamer;
use Rushing\PermissionCascade\Support\CredentialScope;

/**
 * A scoped credential fails closed (fleet ADR 0006 rule 1, amending ADR-0109): for the principal acting with a scoped
 * credential, EVERY Gate decision is "the principal may AND the token carries the decision's name". A decision that
 * resolves to no name refuses the scoped token.
 *
 * Moved here from beam (standwell gap-assessment-build 39 built it there as `Splicewire\Beam\Authorization\
 * CredentialScopeGate`, narrowing only flat permission names); beam keeps only its registration as the first
 * `Gate::before`. The cascade stays credential-agnostic: the scope comes from the bound
 * {@see CredentialScopeResolver} (beam-accounts binds the Sanctum one).
 *
 * **A decision's name** ({@see namesFor()}), first match wins:
 *
 *  1. a flat permission name (`declarations.check`, `tenant:provision`) is its own name;
 *  2. a name registered in {@see DecisionNames} (a decision with no subject or verb, or a host's explicit naming);
 *  3. the names the subject's policy declares ({@see NamesDecisions}; `BaseModelPolicy` names its rungs);
 *  4. the cascade's derivation for a verb on a model subject: `{model}.{verb}` (class or instance) and
 *     `{model}.{id}.{verb}` (a persisted instance), the verb as written and kebab-cased (`forceDelete` →
 *     `force-delete`), `viewAny` also as `view`. Membership, ownership, participant and seller arms are named this way
 *     too: they are verbs of a policy on a subject.
 *  5. nothing: the decision is UNNAMED and a scoped token is refused ({@see CredentialScopeRefusal::UNNAMED}).
 *
 * A carried name only admits the decision: {@see before()} answers `null` and the rest of the chain (the host's
 * befores, the policy, spatie) still decides for the principal. A name not carried is refused
 * ({@see CredentialScopeRefusal::NOT_CARRIED}). Every refusal is a coded 403.
 *
 * Unchanged, on purpose:
 *
 *  - the ENTITLEMENT plane (`entitlement:{key}`): a plan feature of the tenant, answered principal-only under a scope,
 *    permissions its definition asks included ({@see principalOnly()}; ADR 0006 C4);
 *  - an unscoped call: a session, a `['*']` token, an unknown token, no bound resolver;
 *  - a guest, and a check made for anyone but the request's authenticated principal (a recipient, another member):
 *    the scope belongs to the credential that authenticated THIS request.
 *
 * {@see superuser()} and {@see superuserMay()} serve a host's allow-all `Gate::before` (the flagship's Root) and Root
 * arms inside policies: under a scope a superuser grant answers only for a name the token carries.
 */
class CredentialScopeGate
{
    public const ENTITLEMENT_PREFIX = 'entitlement:';

    /**
     * How deep the current evaluation is inside an entitlement check answered principal-only ({@see before()}). While
     * it is above zero no scope governs any check, so an entitlement definition that asks a permission internally
     * (`entitlement:analytics.view` => `$user->can('analytics.view')`) keeps its principal answer.
     */
    protected static int $principalOnly = 0;

    public function __construct(protected Gate $gate, protected DecisionNames $decisionNames) {}

    /**
     * Whether a narrowing credential scope governs checks made for `$user`: a resolver is bound, the request's
     * credential is scoped, and `$user` is the request's authenticated principal.
     */
    public function scopes(mixed $user): bool
    {
        if ($user === null
            || static::$principalOnly > 0
            || ! app()->bound(CredentialScopeResolver::class)
            || ! app(CredentialScope::class)->isScoped()) {
            return false;
        }

        return $this->isActingPrincipal($user);
    }

    /** Whether the acting credential's scope carries `$permission` (unscoped: always). */
    public function permits(string $permission): bool
    {
        return ! app()->bound(CredentialScopeResolver::class) || app(CredentialScope::class)->permits($permission);
    }

    /**
     * The `Gate::before` body (beam registers it first): under a scope, a decision whose name the token carries is left
     * to the rest of the chain (`null`); a decision whose name it lacks, or that has no name, is refused with a coded
     * {@see CredentialScopeRefusal}. Every unscoped check, and every check for another principal or a guest, is `null`.
     *
     * An ENTITLEMENT check under a scope is answered here (`true`/`false`), by the full chain evaluated
     * principal-only: the plane is exempt, and an entitlement definition may ask a permission internally (the
     * flagship's `entitlement:analytics.view` asks `analytics.view`). The same permission asked directly stays narrowed.
     *
     * @param  array<int, mixed>|mixed  $arguments
     */
    public function before(mixed $user, mixed $ability, mixed $arguments = []): bool|CredentialScopeRefusal|null
    {
        if (! is_string($ability) || ! $this->scopes($user)) {
            return null;
        }

        $arguments = is_array($arguments) ? array_values($arguments) : [$arguments];

        if (str_starts_with($ability, self::ENTITLEMENT_PREFIX)) {
            return $this->principalOnly(fn (): bool => $this->gate->forUser($user)->allows($ability, $arguments));
        }

        $names = $this->namesFor($ability, $arguments);

        if ($names === []) {
            return CredentialScopeRefusal::unnamed($ability);
        }

        return $this->permitsAny($names) ? null : CredentialScopeRefusal::notCarried($ability, $names);
    }

    /**
     * The names that admit `$ability` with `$arguments` for a scoped credential (see the class doc for the order). An
     * empty list: the decision is unnamed.
     *
     * @param  array<int, mixed>  $arguments
     * @return list<string>
     */
    public function namesFor(string $ability, array $arguments = []): array
    {
        if (self::isPermissionName($ability)) {
            return [$ability];
        }

        $registered = $this->decisionNames->for($ability, $arguments);
        if ($registered !== null) {
            return $registered;
        }

        $subject = $arguments[0] ?? null;
        $policy = $this->policyFor($subject);
        if ($policy instanceof NamesDecisions) {
            $declared = $policy->decisionNames($ability, $arguments);
            if ($declared !== null) {
                return array_values(array_unique($declared));
            }
        }

        return $this->derivedNames($ability, $subject);
    }

    /**
     * Every class-level name a scoped token can usefully carry (fleet ADR 0006, "Everything I hold"; credential-scope
     * 04): the names registered in {@see DecisionNames}, and for every policy the Gate knows (`Gate::policies()`, the
     * cascade registrar's included) each public verb's names on the policed model CLASS, as {@see namesFor()} answers
     * them (a policy's {@see NamesDecisions} answer, else the derivation). Never a per-record `{model}.{id}.{verb}`
     * name: those are unbounded, and a token that needs one names it explicitly.
     *
     * Offering a name never grants it: the principal half of every decision still applies. beam-accounts' widest token
     * set reads this.
     *
     * @return list<string>
     */
    public function offerableNames(): array
    {
        $names = $this->decisionNames->registered();

        if ($this->gate instanceof LaravelGate) {
            foreach (array_keys($this->gate->policies()) as $model) {
                if (! is_string($model) || ! is_subclass_of($model, Model::class)) {
                    continue;
                }

                $policy = $this->policyFor($model);
                if (! is_object($policy)) {
                    continue;
                }

                foreach ($this->policyVerbs($policy) as $verb) {
                    try {
                        array_push($names, ...$this->namesFor($verb, [$model]));
                    } catch (\Throwable) {
                        // A registered closure written for a record (`$arguments[0]->getKey()`) has no class-level
                        // answer: it names per call, so there is nothing to offer for it here.
                    }
                }
            }
        }

        return array_values(array_unique(array_filter($names, fn ($name) => is_string($name) && $name !== '' && $name !== '*')));
    }

    /**
     * A policy's verbs: its public instance methods, less the hooks and helpers that are no decision (`before`,
     * `after`, `decisionNames`, `scopeForUser`, magic methods) and anything Laravel's own traits declare
     * (`HandlesAuthorization`'s `allow`/`deny`).
     *
     * @return list<string>
     */
    protected function policyVerbs(object $policy): array
    {
        $verbs = [];

        foreach ((new \ReflectionObject($policy))->getMethods(\ReflectionMethod::IS_PUBLIC) as $method) {
            $name = $method->getName();

            if ($method->isStatic()
                || str_starts_with($name, '__')
                || in_array($name, ['before', 'after', 'decisionNames', 'scopeForUser'], true)
                || str_starts_with($method->getDeclaringClass()->getName(), 'Illuminate\\')
                || $this->declaredByIlluminateTrait($method)) {
                continue;
            }

            $verbs[] = $name;
        }

        return $verbs;
    }

    protected function declaredByIlluminateTrait(\ReflectionMethod $method): bool
    {
        foreach ($method->getDeclaringClass()->getTraits() as $trait) {
            if (str_starts_with($trait->getName(), 'Illuminate\\') && $trait->hasMethod($method->getName())) {
                return true;
            }
        }

        return false;
    }

    /**
     * The cascade's derived names for a verb on a model subject: `{model}.{verb}` and, for a persisted instance,
     * `{model}.{id}.{verb}`; the verb as written and kebab-cased; `viewAny` also as `view`. Empty when the subject is no
     * model (a guest-less ability with no subject, a plain object, a scalar): nothing to derive from.
     *
     * @return list<string>
     */
    public function derivedNames(string $verb, mixed $subject): array
    {
        $class = match (true) {
            $subject instanceof Model => get_class($subject),
            is_string($subject) && is_subclass_of($subject, Model::class) => $subject,
            default => null,
        };

        if ($class === null) {
            return [];
        }

        $verbs = array_unique(array_filter([$verb, Str::kebab($verb), $verb === 'viewAny' ? 'view' : null]));
        $names = [];

        foreach ($verbs as $each) {
            $names[] = PermissionNamer::assemble($class, $each);

            if ($subject instanceof Model && $subject->exists) {
                $names[] = PermissionNamer::assemble($subject, $each);
            }
        }

        return array_values(array_unique($names));
    }

    /**
     * Run `$check` with no scope governing any check it makes (see {@see $principalOnly}).
     *
     * @template T
     *
     * @param  Closure(): T  $check
     * @return T
     */
    public function principalOnly(Closure $check): mixed
    {
        static::$principalOnly++;

        try {
            return $check();
        } finally {
            static::$principalOnly--;
        }
    }

    /**
     * The answer a host's allow-all (superuser) `Gate::before` gives for `$user`: `true` when no scope governs the
     * check, as before. Under a scope: the entitlement plane `true`; otherwise `true` only when the token carries the
     * decision's strict name ({@see superuserMay()}), or the decision's own definition allows it with the before
     * callbacks removed (so the checks the definition makes are narrowed one by one).
     *
     * @param  array<int, mixed>  $arguments  the check's arguments, as a `Gate::before` receives them
     */
    public function superuser(mixed $user, mixed $ability, array $arguments = []): bool
    {
        if (! is_string($ability)) {
            return true;
        }

        if ($this->superuserMay($user, $ability, $arguments[0] ?? null)) {
            return true;
        }

        return ! self::isPermissionName($ability) && $this->definitionAllows($user, $ability, $arguments);
    }

    /**
     * The narrower half of {@see superuser()}, for a superuser grant made INSIDE a policy (a policy `before`, an
     * `isRoot()` arm) or a role fallback beside the cascade, where evaluating the definition again would recurse:
     * `true` when no scope governs the check; under a scope, a flat name by the scope and a verb by its strict name
     * only: a registered name, or the derived `{model}.{verb}` / `{model}.{id}.{verb}`. A policy's own rung names
     * (`{model}.own.{verb}`) do not count: a superuser grant is not ownership.
     */
    public function superuserMay(mixed $user, string $ability, mixed $subject = null): bool
    {
        if (str_starts_with($ability, self::ENTITLEMENT_PREFIX) || ! $this->scopes($user)) {
            return true;
        }

        return self::isPermissionName($ability) ? $this->permits($ability) : $this->permitsVerb($ability, $subject);
    }

    /**
     * Whether the scope carries a verb's strict name: its registered name, else its derived `{model}.{verb}` /
     * `{model}.{id}.{verb}`. A verb with no model subject and no registered name has no name: false.
     */
    public function permitsVerb(string $verb, mixed $subject = null): bool
    {
        $arguments = $subject === null ? [] : [$subject];

        return $this->permitsAny($this->decisionNames->for($verb, $arguments) ?? $this->derivedNames($verb, $subject));
    }

    /** @param  list<string>  $names */
    public function permitsAny(array $names): bool
    {
        foreach ($names as $name) {
            if ($this->permits($name)) {
                return true;
            }
        }

        return false;
    }

    /** A flat namespaced name (`declarations.check`, `tenant:provision`), not a bare verb or an entitlement key. */
    public static function isPermissionName(string $ability): bool
    {
        return ! str_starts_with($ability, self::ENTITLEMENT_PREFIX)
            && (str_contains($ability, '.') || str_contains($ability, ':'));
    }

    /** The policy the Gate resolves for `$subject` (a model instance or class), or null. */
    protected function policyFor(mixed $subject): mixed
    {
        if (! (is_object($subject) || (is_string($subject) && class_exists($subject)))) {
            return null;
        }

        try {
            return $this->gate->getPolicyFor($subject);
        } catch (\Throwable) {
            return null;
        }
    }

    /**
     * The check answered by its own definition (policy method, policy `before`, `Gate::define` callback) with every
     * `Gate::before` removed, so a superuser grant cannot answer it. Checks the definition makes in turn go through
     * the full Gate, where {@see before()} narrows them and the host's superuser `before` answers them here.
     *
     * @param  array<int, mixed>  $arguments
     */
    protected function definitionAllows(mixed $user, string $ability, array $arguments): bool
    {
        if (! $this->gate instanceof LaravelGate) {
            return false;
        }

        $bare = $this->gate->forUser($user);
        Closure::bind(fn () => $this->beforeCallbacks = [], $bare, LaravelGate::class)();

        return $bare->allows($ability, $arguments);
    }

    /**
     * Whether `$user` is a principal this request authenticated: the user any already-resolved guard holds (a named
     * guard such as `sanctum` included, so `Gate::forUser(auth('sanctum')->user())` is narrowed while the default
     * guard is empty or holds someone else), or the default request user. Same object, or the same auth identifier
     * (a tenant `TenantUser` mirror shares its central user's). Any other user is not narrowed.
     */
    protected function isActingPrincipal(mixed $user): bool
    {
        foreach ($this->resolvedGuardUsers() as $acting) {
            if ($this->samePrincipal($acting, $user)) {
                return true;
            }
        }

        $request = app()->bound('request') ? app('request') : null;

        return $this->samePrincipal($request?->user(), $user);
    }

    /** @return list<mixed> the users the auth manager's already-resolved guards hold, resolving no new guard */
    protected function resolvedGuardUsers(): array
    {
        $auth = app()->bound('auth') ? app('auth') : null;

        if (! $auth instanceof AuthManager) {
            return [];
        }

        $guards = Closure::bind(fn (): array => $this->guards, $auth, AuthManager::class)();
        $users = [];

        foreach ($guards as $guard) {
            if (method_exists($guard, 'hasUser') && $guard->hasUser()) {
                $users[] = $guard->user();
            }
        }

        return $users;
    }

    protected function samePrincipal(mixed $acting, mixed $user): bool
    {
        if ($acting === null) {
            return false;
        }

        if ($acting === $user) {
            return true;
        }

        if (! $acting instanceof Authenticatable || ! $user instanceof Authenticatable) {
            return false;
        }

        $actingId = $acting->getAuthIdentifier();

        return $actingId !== null && (string) $actingId === (string) $user->getAuthIdentifier();
    }
}
