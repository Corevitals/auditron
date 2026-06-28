<?php

/**
 * Contract <<projectversion>>
 * Author: Timothy Lorens (tlorens@corevitals.com)
 * File: CheckInterface.php
 * Created: Sunday, June 28th 2026
 * -----
 * Last Modified: Sunday June 28th 2026 3:22 pm
 * Modified By: Timothy Lorens (tlorens@corevitals.com)
 * -----
 * Copyright 2020 - 2026, CoreVitals, LLC
 */

declare(strict_types=1);

namespace Corevitals\Auditron\Contract;

use Corevitals\Auditron\Domain\CheckResult;

interface CheckInterface
{
    /**
     * The human-readable name of the security check.
     */
    public function getName(): string;

    /**
     * A brief explanation of what the check verifies.
     */
    public function getDescription(): string;

    /**
     * Executes the security audit logic.
     */
    public function run(): CheckResult;
}
