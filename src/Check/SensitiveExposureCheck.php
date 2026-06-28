<?php

/**
 * Auditron v1.0.0
 * Author: Timothy Lorens (tlorens@corevitals.com)
 * File: SensitiveExposureCheck.php
 * Created: Sunday, June 28th 2026
 * -----
 * Last Modified: Sunday June 28th 2026 4:55 pm
 * Modified By: Timothy Lorens (tlorens@corevitals.com>)
 * -----
 * Copyright 2020 - 2026, CoreVitals, LLC
 */

declare(strict_types=1);

namespace Corevitals\Auditron\Check;

use Corevitals\Auditron\Domain\CheckResult;
use Symfony\Component\Finder\Finder;

final class SensitiveExposureCheck extends AbstractCheck
{
    private const DANGEROUS_INI_SETTINGS = ['display_errors', 'error_reporting'];
    private const LOGGER_METHODS         = ['info', 'debug', 'warning', 'error', 'critical', 'alert', 'emergency'];
    private const SENSITIVE_VAR_PATTERNS = ['password', 'secret', 'token', 'auth', 'key'];

    public function getName(): string
    {
        return 'Sensitive Exposure Audit';
    }

    public function getDescription(): string
    {
        return 'Detects runtime changes to PHP INI settings and potential logging of sensitive variables.';
    }

    public function run(): CheckResult
    {
        $srcPath = getcwd() . DIRECTORY_SEPARATOR . 'src';
        $finder = new Finder();
        $finder->files()->in($srcPath)->name('*.php');

        $violations = [];

        foreach ($finder as $file) {
            $tokens = token_get_all($file->getContents());
            $filePath = $file->getRelativePathname();

            for ($i = 0; $i < count($tokens); $i++) {
                $token = $tokens[$i];

                if (!is_array($token)) continue;

                // Detect ini_set() abuse
                if ($token[0] === T_STRING && strtolower($token[1]) === 'ini_set') {
                    // Peek at the first argument
                    $arg = $this->getArgument($tokens, $i + 1);
                    if ($arg !== null && in_array(trim($arg, "'\""), self::DANGEROUS_INI_SETTINGS, true)) {
                        $violations[] = sprintf('Potentially dangerous ini_set("%s") found in %s on line %d.', $arg, $filePath, $token[2]);
                    }
                }

                // Detect Logger + Sensitive Variable concatenation
                if ($token[0] === T_OBJECT_OPERATOR) {
                    $methodName = $this->getNextString($tokens, $i + 1);
                    if ($methodName !== null && in_array(strtolower($methodName), self::LOGGER_METHODS, true)) {
                        // Check if a sensitive variable is passed in the next few tokens
                        if ($this->hasSensitiveConcatenation($tokens, $i + 1)) {
                            $violations[] = sprintf('Potential sensitive data logging detected in method "->%s()" in %s on line %d.', $methodName, $filePath, $token[2]);
                        }
                    }
                }
            }
        }

        if (!empty($violations)) {
            return $this->fail(
                $violations,
                'Remediation: 1) Move INI configuration to php.ini or environment files. 2) For logging, use a "masking" utility to redact sensitive values before they hit the logger.'
            );
        }

        return $this->pass(['No runtime INI overrides or obvious sensitive logging patterns found.']);
    }

    private function getArgument(array $tokens, int $startIndex): ?string
    {
        for ($i = $startIndex; $i < count($tokens); $i++) {
            if ($tokens[$i] === '(') continue;
            if (is_array($tokens[$i]) && $tokens[$i][0] === T_CONSTANT_ENCAPSED_STRING) return $tokens[$i][1];
            break;
        }
        return null;
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

    private function hasSensitiveConcatenation(array $tokens, int $startIndex): bool
    {
        // Scan tokens up to the closing parenthesis for variable patterns
        for ($i = $startIndex; $i < count($tokens); $i++) {
            $t = $tokens[$i];
            if ($t === ')') break;
            if (is_array($t) && $t[0] === T_VARIABLE) {
                foreach (self::SENSITIVE_VAR_PATTERNS as $pattern) {
                    if (str_contains(strtolower($t[1]), $pattern)) return true;
                }
            }
        }
        return false;
    }
}
