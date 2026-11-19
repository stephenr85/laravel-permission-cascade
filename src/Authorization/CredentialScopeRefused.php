<?php

namespace Rushing\PermissionCascade\Authorization;

use Illuminate\Auth\Access\AuthorizationException;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

/**
 * A scoped credential refused at a Gate decision ({@see CredentialScopeRefusal}). It IS an
 * {@see AuthorizationException}, so every `catch` keeps working and the framework answers 403. A request that expects
 * JSON gets `{message, code}`, the shape beam's coded errors render.
 */
class CredentialScopeRefused extends AuthorizationException
{
    public function __construct(protected CredentialScopeRefusal $refusal)
    {
        parent::__construct($refusal->message(), $refusal->errorCode());
        $this->setResponse($refusal);
    }

    /** The stable wire code. */
    public function errorCode(): string
    {
        return $this->refusal->errorCode();
    }

    public function render(Request $request): ?JsonResponse
    {
        if (! $request->expectsJson()) {
            return null;
        }

        return new JsonResponse([
            'message' => CredentialScopeRefusal::describe($this->refusal->errorCode(), $this->refusal->params()),
            'code' => $this->refusal->errorCode(),
        ], $this->status() ?? 403);
    }
}
