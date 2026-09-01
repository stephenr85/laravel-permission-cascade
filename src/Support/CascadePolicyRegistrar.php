<?php

namespace Rushing\PermissionCascade\Support;

use Illuminate\Support\Facades\Gate;
use LogicException;
use ReflectionClass;
use Rushing\PermissionCascade\Attributes\UseCascadePolicy;
use Rushing\PermissionCascade\Policies\BaseModelPolicy;
use Rushing\PermissionCascade\Policies\ConfiguredModelPolicy;

/**
 * Wires a `#[UseCascadePolicy]`-carrying model onto the Gate — the registration half the attribute
 * alone can't do (declaring it on a model is inert; nothing scans for it automatically). A host's
 * service provider calls one of these from `boot()`, in place of a `Gate::policy($model, $policy)`
 * call naming a hand-written subclass.
 *
 * Binds each model's {@see ConfiguredModelPolicy} under a synthetic, per-model container key
 * (`permission-cascade-policy:<model>`) rather than registering `ConfiguredModelPolicy::class`
 * directly — Laravel's `Gate::policy()` only ever stores a class-string and resolves it via
 * `$container->make($class)` with no way to pass constructor args through that call, so a bare
 * class-string can't carry per-model config. The synthetic key is an ordinary container binding (a
 * closure building the configured instance), which `make()` resolves exactly like any other bound
 * abstract.
 */
class CascadePolicyRegistrar
{
    /**
     * Register one model's `#[UseCascadePolicy]` (if it carries one) onto the Gate.
     *
     * @return bool whether the model carried the attribute and was registered
     */
    public static function register(string $modelClass): bool
    {
        $attributes = (new ReflectionClass($modelClass))->getAttributes(UseCascadePolicy::class);

        if ($attributes === []) {
            return false;
        }

        $attribute = $attributes[0]->newInstance();

        if ($attribute->policy !== BaseModelPolicy::class && ! is_subclass_of($attribute->policy, BaseModelPolicy::class)) {
            throw new LogicException(
                "UseCascadePolicy on {$modelClass}: {$attribute->policy} must be ".BaseModelPolicy::class.' or a subclass.'
            );
        }

        // An override naming an ability ConfiguredModelPolicy has no method for could never have
        // fired, and until 2026-09-01 it did worse than nothing: the `__call()` that served it made
        // `is_callable()` true for EVERY ability name, so the policy won Gate resolution for abilities
        // it had never heard of and denied them, shadowing the host's `Gate::define()`. The magic
        // method is gone; refusing the override that depended on it keeps the removal honest rather
        // than turning a declared `true` into a silent no-op.
        //
        // This is a grammar fault, not a host fact — the attribute's author could have gotten it right
        // without knowing which host would load the model — so it throws, like the `$policy` check
        // above. Measured 2026-09-01: zero declarations estate-wide name a non-standard ability
        // (all 20 use only `create` and `update`), so nothing that exists today can trip it.
        $unknown = array_diff(array_keys($attribute->overrides), ConfiguredModelPolicy::STANDARD_ABILITIES);

        if ($unknown !== []) {
            throw new LogicException(
                "UseCascadePolicy on {$modelClass}: override(s) ".implode(', ', $unknown)
                .' name no ability '.ConfiguredModelPolicy::class.' can answer. Overrides are limited to '
                .implode(', ', ConfiguredModelPolicy::STANDARD_ABILITIES)
                .'; a custom ability belongs in a Gate::define(), which the policy no longer shadows.'
            );
        }

        $key = 'permission-cascade-policy:'.$modelClass;

        app()->bind($key, fn () => new ConfiguredModelPolicy($modelClass, $attribute->overrides));

        Gate::policy($modelClass, $key);

        return true;
    }

    /** @param iterable<class-string> $modelClasses */
    public static function registerMany(iterable $modelClasses): void
    {
        foreach ($modelClasses as $modelClass) {
            static::register($modelClass);
        }
    }

    /**
     * Every class under `$directory` (non-recursive PSR-4 mapping to `$namespace`) that exists and
     * carries `#[UseCascadePolicy]`. A plain filesystem glob, re-run each boot — fine for a handful
     * of model files; a host with many should list classes explicitly (`registerMany`) instead of
     * paying a per-boot directory walk.
     *
     * @return list<class-string>
     */
    public static function discover(string $directory, string $namespace): array
    {
        $found = [];

        foreach (glob(rtrim($directory, '/').'/*.php') ?: [] as $file) {
            $class = rtrim($namespace, '\\').'\\'.basename($file, '.php');

            if (class_exists($class) && (new ReflectionClass($class))->getAttributes(UseCascadePolicy::class) !== []) {
                $found[] = $class;
            }
        }

        return $found;
    }

    public static function registerDiscovered(string $directory, string $namespace): void
    {
        static::registerMany(static::discover($directory, $namespace));
    }
}
