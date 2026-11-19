<?php

namespace Rushing\PermissionCascade\Authorization;

use Closure;
use Illuminate\Auth\Access\Response;

/**
 * The Gate's answer when a scoped credential is refused at a decision (fleet ADR 0006 C1, C2): a denied
 * {@see Response} carrying a stable code, so `Gate::authorize()`, a `can:` route and a controller's `authorize()` throw
 * {@see CredentialScopeRefused}, which renders a coded 403. `Gate::allows()` and `$user->can()` simply answer false.
 *
 *  - {@see UNNAMED}: the decision resolves to no name at all (no permission name, no derivable model subject, nothing
 *    registered), so no scope can carry it.
 *  - {@see NOT_CARRIED}: the decision has a name, and the token does not carry it.
 *
 * The message is English by default. A host that localizes coded errors (beam) supplies it through
 * {@see describeUsing()}; the code never changes.
 */
class CredentialScopeRefusal extends Response
{
    public const UNNAMED = 'credential_scope_unnamed_decision';

    public const NOT_CARRIED = 'credential_scope_name_not_carried';

    /** @var (Closure(string, array<string, scalar>): ?string)|null */
    protected static ?Closure $describer = null;

    /** @param  array<string, scalar>  $params */
    public function __construct(protected string $errorCode, protected array $params = [])
    {
        parent::__construct(false, static::describe($errorCode, $params), $errorCode);
        $this->withStatus(403);
    }

    public static function unnamed(string $ability): static
    {
        return new static(self::UNNAMED, ['ability' => $ability]);
    }

    /** @param  list<string>  $names */
    public static function notCarried(string $ability, array $names): static
    {
        return new static(self::NOT_CARRIED, ['ability' => $ability, 'names' => implode(', ', $names)]);
    }

    /**
     * Supply the message for a code (a host's coded-error catalog). Null restores the English default.
     *
     * @param  (Closure(string, array<string, scalar>): ?string)|null  $describer
     */
    public static function describeUsing(?Closure $describer): void
    {
        static::$describer = $describer;
    }

    /** @param  array<string, scalar>  $params */
    public static function describe(string $code, array $params = []): string
    {
        $described = static::$describer !== null ? (static::$describer)($code, $params) : null;

        if (is_string($described) && $described !== '') {
            return $described;
        }

        return $code === self::UNNAMED
            ? "This token cannot be used for [{$params['ability']}], a decision with no name a token can carry."
            : "This token does not carry the name [{$params['ability']}] requires.";
    }

    public function errorCode(): string
    {
        return $this->errorCode;
    }

    /** @return array<string, scalar> */
    public function params(): array
    {
        return $this->params;
    }

    public function authorize()
    {
        throw (new CredentialScopeRefused($this))->withStatus($this->status());
    }
}
