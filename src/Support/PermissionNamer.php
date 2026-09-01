<?php

namespace Rushing\PermissionCascade\Support;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Log;

class PermissionNamer
{
    /**
     * Parts already warned about, so a single un-aliased model logs ONCE per process.
     *
     * Deduplication is not tidiness, it is what makes the warning usable. `BaseModelPolicy::allowed()`
     * calls `assemble()` up to three times per authorization check and the visibility-scope builder calls
     * it again per index query, so a per-call warning would fire on every request for every user; and a
     * host's `PermissionsSeeder` fans ~34 `names()` calls out to several hundred `assemble()` calls per
     * tenant. Per-call is a flood, which is indistinguishable from noise and gets silenced. The namer is
     * bound as a singleton, so instance state gives per-process dedup for free.
     *
     * @var array<string, true>
     */
    protected array $warnedUnaliased = [];

    public function assemble(...$parts)
    {
        return collect($parts)->filter()
            ->flatMap(function ($part) {
                if ($part instanceof Model) {
                    return [$part->getMorphClass(), $part->getKey()];
                } elseif (is_subclass_of($part, Model::class)) {
                    return [$part::make()->getMorphClass()];
                } elseif (is_iterable($part)) {
                    return [call_user_func([$this, 'assemble'], $part)];
                }

                return explode('.', $part);
            })
            ->map(function ($part) {
                $this->warnIfUnaliased($part);

                return str($part)->slug();
            })->join('.').'';
    }

    /**
     * Report — never refuse — a part that is still a fully-qualified class name (ADR-0118 decision 7).
     *
     * `getMorphClass()` returns the FQCN when a model is absent from the morph map, and `Str::slug()`
     * then DELETES the backslashes rather than failing: `Splicewire\Tower\Models\Entity` becomes
     * `splicewiretowermodelsentity`, so the token is silently wrong and reads as a real permission
     * everywhere it lands. That is the defect ADR-0118 exists to prevent, and until now the only thing
     * standing between the estate and a table full of mush was that every first-party model happened to
     * be aliased.
     *
     * ⚠️ A warning and not an exception, deliberately. Whether a model is aliased is a fact about the
     * HOST — which packages it composes, which providers booted — so by this estate's standing rule it is
     * an advisory finding. Throwing here would take down a host for a condition the declaration's author
     * could not have gotten right. The gating instrument is `MorphAliasCoverageAudit`, which is advisory
     * permanently for the same reason; this is the runtime half, and it catches what a source scan cannot
     * — a model resolved dynamically at runtime.
     *
     * This is the only place all four `flatMap` branches converge, so one guard here covers model
     * instances, class-strings, iterables and raw strings alike. Note it does NOT cover
     * `ParticleOperation::permissionName()`, which reproduces the token shape without calling this class.
     */
    protected function warnIfUnaliased($part): void
    {
        $value = (string) $part;

        if (! str_contains($value, '\\') || isset($this->warnedUnaliased[$value])) {
            return;
        }

        $this->warnedUnaliased[$value] = true;

        Log::warning('Permission name derived from an un-aliased class — register its morph alias.', [
            'part' => $value,
            'derived' => (string) str($value)->slug(),
            'fix' => 'Relation::morphMap() in the provider of the package that owns the model (ADR-0118).',
        ]);
    }

    public function names($primary, $actions, $qualifiers = [])
    {
        return collect($actions)->flatMap(function ($action, $key) use ($qualifiers, $primary) {
            if (! is_numeric($key)) {
                // Action specifies qualifiers
                $qualifiers = $action;
                $action = $key;
            }
            $set = [];
            foreach (collect($qualifiers ?: ['']) as $qualifier) {
                $set[] = $this->assemble($primary, $qualifier, $action);
            }

            return $set;
        });
    }
}
