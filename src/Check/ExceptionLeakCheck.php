<?php

/**
 * Auditron v1.0.0
 * Author: Timothy Lorens (tlorens@corevitals.com)
 * File: ExceptionLeakCheck.php
 * Created: Sunday, June 28th 2026
 * -----
 * Last Modified: Sunday June 28th 2026 4:57 pm
 * Modified By: Timothy Lorens (tlorens@corevitals.com>)
 * -----
 * Copyright 2020 - 2026, CoreVitals, LLC
 */

declare(strict_types=1);

namespace Corevitals\Auditron\Check;

use Corevitals\Auditron\Domain\CheckResult;
use Symfony\Component\Finder\Finder;

final class ExceptionLeakCheck extends AbstractCheck
{
    private const SENSITIVE_EXCEPTION_METHODS = [
        'getmessage',
        'gettrace',
        'gettraceasstring',
        'getprevious'
    ];

    private const DANGEROUS_OUTPUT_FUNCTIONS = [
        'echo',
        'print',
        'var_dump',
        'printf'
    ];

    public function getName(): string
    {
        return 'Exception Leak Audit';
    }

    public function getDescription(): string
    {
        return 'Detects the logging or outputting of raw exception messages and stack traces, which can leak sensitive system information.';
    }

    public function run(): CheckResult
    {
        $srcPath = getcwd() . DIRECTORY_SEPARATOR . 'src';
        $finder  = new Finder();
        $finder->files()->in($srcPath)->name('*.php');

        $violations = [];

        foreach ($finder as $file) {
            $tokens   = token_get_all($file->getContents());
            $filePath = $file->getRelativePathname();

            for ($i = 0; $i < count($tokens); $i++) {
                $token = $tokens[$i];

                if (!is_array($token) || $token[0] !== T_OBJECT_OPERATOR) {
                    continue;
                }

                // Get the method being called (e.g., ->getMessage())
                $method = $this->getNextString($tokens, $i + 1);
                if ($method === null || !in_array(strtolower($method), self::SENSITIVE_EXCEPTION_METHODS, true)) {
                    continue;
                }

                // We found a call to a sensitive method. Now check the surrounding context.
                if ($this->isInsideDangerousContext($tokens, $i)) {
                    $violations[] = sprintf(
                        'Potential sensitive leak via "%s()" in %s on line %d.',
                        $method,
                        $filePath,
                        $token[2]
                    );
                }
            }
        }

        if (!empty($violations)) {
            return $this->fail(
                $violations,
                'REMEDIATION: Do not log or display raw exception details. Use a custom error message for the user. For logging, wrap the exception in a custom "LoggableException" or use a dedicated logger processor to redact sensitive data.'
            );
        }

        return $this->pass(['Exception handling appears to be sanitized.']);
    }

    private function getNextString(array $tokens, int $startIndex): ?string
    {
        foreach (array_slice($tokens, $startIndex) as $token) {
            if (is_array($token) && $token[0] === T_WHITESPACE) continue;
            if (is_array($token) && $token[0] === T_STRING) return $token[1];
            break;
        }
        return null;
    }

    private function isInsideDangerousContext(array $tokens, int $index): bool
    {
        // Check if used in echo/print/etc
        // Look backwards for a dangerous function
        for ($i = $index - 1; $i > max(0, $index - 10); $i--) {
            $t = $tokens[$i];
            if (is_array($t) && in_array(strtolower($t[1]), self::DANGEROUS_OUTPUT_FUNCTIONS, true)) {
                return true;
            }
        }

        // Check if passed to a logger (heuristic)
        // We look ahead a few tokens to see if it's inside a function call that looks like a logger
        for ($i = $index + 1; $i < min(count($tokens), $index + 10); $i++) {
            $t = $tokens[$i];
            if (is_array($t) && $t[0] === T_STRING && preg_match('/(log|logger|error|warn|crit)/i', $t[1])) {
                return true;
            }
        }

        return false;
    }
}
