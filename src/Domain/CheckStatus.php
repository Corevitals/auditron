<?php

/**
 * Auditron v1.0.0
 * Author: Timothy Lorens (tlorens@corevitals.com)
 * File: CheckStatus.php
 * Created: Sunday, June 28th 2026
 * -----
 * Last Modified: Sunday June 28th 2026 3:20 pm
 * Modified By: Timothy Lorens (tlorens@corevitals.com)
 * -----
 * Copyright 2020 - 2026, CoreVitals, LLC
 */

declare(strict_types=1);

namespace Corevitals\Auditron\Domain;

enum CheckStatus: string
{
    case PASSED  = 'passed';
    case FAILED  = 'failed';
    case WARNING = 'warning';
    case SKIPPED = 'skipped';
}
