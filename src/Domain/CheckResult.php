<?php

/**
 * Domain <<projectversion>>
 * Author: Timothy Lorens (tlorens@corevitals.com)
 * File: CheckResult.php
 * Created: Sunday, June 28th 2026
 * -----
 * Last Modified: Sunday June 28th 2026 3:21 pm
 * Modified By: Timothy Lorens (tlorens@corevitals.com)
 * -----
 * Copyright 2020 - 2026, CoreVitals, LLC
 */

declare(strict_types=1);

namespace Corevitals\Auditron\Domain;

readonly class CheckResult
{
    /**
     * @param array<int, string> $messages Contextual output, violations, or fix instructions.
     */
    public function __construct(
        public string $checkName,
        public CheckStatus $status,
        public array $messages = []
    ) {}

    /**
     * Determines if the check allows the overall audit to continue.
     * Warnings are considered successful but should be logged.
     */
    public function isSuccessful(): bool
    {
        return match ($this->status) {
            CheckStatus::PASSED,
            CheckStatus::WARNING,
            CheckStatus::SKIPPED => true,
            CheckStatus::FAILED  => false,
        };
    }
}
