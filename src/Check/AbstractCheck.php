<?php

/**
 * Auditron v1.0.0
 * Author: Timothy Lorens (tlorens@corevitals.com)
 * File: AbstractCheck.php
 * Created: Sunday, June 28th 2026
 * -----
 * Last Modified: Sunday June 28th 2026 3:23 pm
 * Modified By: Timothy Lorens (tlorens@corevitals.com>)
 * -----
 * Copyright 2020 - 2026, CoreVitals, LLC
 */

declare(strict_types=1);

namespace Corevitals\Auditron\Check;

use Corevitals\Auditron\Contract\CheckInterface;
use Corevitals\Auditron\Domain\CheckResult;
use Corevitals\Auditron\Domain\CheckStatus;

abstract class AbstractCheck implements CheckInterface
{
    /**
     * @param array<int, string> $messages
     */
    protected function pass(array $messages = []): CheckResult
    {
        return new CheckResult($this->getName(), CheckStatus::PASSED, $messages);
    }

    /**
     * @param array<int, string> $messages
     */
    protected function fail(array $messages = []): CheckResult
    {
        return new CheckResult($this->getName(), CheckStatus::FAILED, $messages);
    }

    /**
     * @param array<int, string> $messages
     */
    protected function warning(array $messages = []): CheckResult
    {
        return new CheckResult($this->getName(), CheckStatus::WARNING, $messages);
    }

    /**
     * @param array<int, string> $messages
     */
    protected function skip(array $messages = []): CheckResult
    {
        return new CheckResult($this->getName(), CheckStatus::SKIPPED, $messages);
    }
}
