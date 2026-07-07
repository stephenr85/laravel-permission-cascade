<?php

namespace Rushing\PermissionCascade\Support;

use Illuminate\Database\Eloquent\Model;

class PermissionNamer
{
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
            ->map(fn ($part) => str($part)->slug())->join('.').'';
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
