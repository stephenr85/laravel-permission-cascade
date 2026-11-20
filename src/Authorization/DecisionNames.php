<?php

namespace Rushing\PermissionCascade\Authorization;

use Closure;

/**
 * The explicit decision-name registry (fleet ADR 0006 C2): a name for a Gate decision the cascade cannot derive, one
 * with no model subject (`Gate::define('reviewMarketListing', …)`, `viewPulse`) or whose derived name is not the name
 * its owner wants a token to carry.
 *
 * The package that owns the decision registers its name, in its own provider (naming is local; enforcement is
 * central):
 *
 *     app(DecisionNames::class)->name('reviewMarketListing', 'market-listing.review');
 *     app(DecisionNames::class)->name('publish', 'post.publish', Post::class);   // per subject class
 *     app(DecisionNames::class)->name('join', fn (array $arguments) => ['team.'.$arguments[0]->getKey().'.join']);
 *
 * A host may also list names in `config('permission-cascade.decision_names')` (`ability => name|list`). A registered
 * name wins over a policy's {@see \Rushing\PermissionCascade\Contracts\NamesDecisions} answer and over the derivation.
 */
class DecisionNames
{
    /** @var array<string, array<string, list<string>|Closure>> ability => subject class ('' for any) => names */
    protected array $names = [];

    /**
     * Name `$ability` (for `$subject`, a class the check's first argument is or is an instance of; null for any).
     *
     * @param  string|list<string>|Closure(array<int, mixed>): (string|list<string>)  $names
     */
    public function name(string $ability, string|array|Closure $names, ?string $subject = null): static
    {
        $this->names[$ability][$subject ?? ''] = $names instanceof Closure ? $names : array_values((array) $names);

        return $this;
    }

    /**
     * The registered names for `$ability` with `$arguments`, or null when nothing is registered for it.
     *
     * @param  array<int, mixed>  $arguments
     * @return list<string>|null
     */
    public function for(string $ability, array $arguments): ?array
    {
        $entries = $this->entries($ability);

        if ($entries === []) {
            return null;
        }

        $subject = $arguments[0] ?? null;
        $class = is_object($subject) ? get_class($subject) : (is_string($subject) && class_exists($subject) ? $subject : null);

        $names = null;
        if ($class !== null) {
            foreach ($entries as $for => $candidate) {
                if ($for !== '' && is_a($class, $for, true)) {
                    $names = $candidate;
                    break;
                }
            }
        }
        $names ??= $entries[''] ?? null;

        if ($names === null) {
            return null;
        }

        return array_values(array_filter(
            (array) ($names instanceof Closure ? $names($arguments) : $names),
            fn ($name) => is_string($name) && $name !== '',
        ));
    }

    /**
     * Every name registered as a list, here or in `config('permission-cascade.decision_names')`, for the widest set a
     * token may be scoped to (fleet ADR 0006, "Everything I hold"; credential-scope 04). A name registered as a closure
     * is skipped: it names one call's arguments (a record, a team), so it has no class-level name to offer.
     *
     * @return list<string>
     */
    public function registered(): array
    {
        $names = [];

        foreach ($this->names as $entries) {
            foreach ($entries as $candidate) {
                if (! $candidate instanceof Closure) {
                    array_push($names, ...$candidate);
                }
            }
        }

        foreach ((array) config('permission-cascade.decision_names', []) as $configured) {
            array_push($names, ...array_values((array) $configured));
        }

        return array_values(array_unique(array_filter($names, fn ($name) => is_string($name) && $name !== '')));
    }

    /** @return array<string, list<string>|Closure> */
    protected function entries(string $ability): array
    {
        $entries = $this->names[$ability] ?? [];
        $configured = config('permission-cascade.decision_names', [])[$ability] ?? null;

        if ($configured !== null && ! array_key_exists('', $entries)) {
            $entries[''] = array_values((array) $configured);
        }

        return $entries;
    }
}
