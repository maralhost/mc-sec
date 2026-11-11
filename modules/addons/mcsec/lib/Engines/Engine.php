<?php

declare(strict_types=1);

namespace McSec\Engines;

/**
 * A scan backend. Scans (the orchestrator) calls, from the worker only:
 *   start()   → begin the work on the backend; returns the backend reference
 *   poll()    → status/progress (cheap; also used by the live progress poll behind a circuit breaker)
 *   collect() → normalized results once poll() said completed
 *   cancel()  → best effort
 * Results are engine-agnostic:
 *   findings: ['key','title','severity','location','description','evidence','solution','refs','cve','cwe','cvss','epss','tags','kb']
 *   surface:  ['kind' => host|port|tech|cert|url|dns, 'value', 'meta' => []]
 */
interface Engine
{
    public function key(): string;

    /** Configured enough to be offered to customers. */
    public function configured(): bool;

    /** @return array{ok:bool,ref?:string,meta?:array,error?:string,retry?:bool,progress?:int,stage?:string} */
    public function start(object $scan, object $asset, array $profile): array;

    /** @return array{status:string,progress?:int,stage?:string,error?:string,meta?:array} status: running|completed|failed */
    public function poll(object $scan, object $asset, array $profile): array;

    /** @return array{findings:array,surface:array,kinds:string[],complete:bool} kinds = surface kinds fully covered */
    public function collect(object $scan, object $asset, array $profile): array;

    public function cancel(object $scan, object $asset): bool;

    /** @return array{ok:bool,message:string,version?:string,ms?:int} */
    public function health(): array;
}
