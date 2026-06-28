<?php

/**
 * Auditron v1.0.0
 * Author: Timothy Lorens (tlorens@corevitals.com)
 * File: ForbiddenFunctionsCheck.php
 * Created: Sunday, June 28th 2026
 * -----
 * Last Modified: Sunday June 28th 2026 3:51 pm
 * Modified By: Timothy Lorens (tlorens@corevitals.com>)
 * -----
 * Copyright 2020 - 2026, CoreVitals, LLC
 */

declare(strict_types=1);

namespace Corevitals\Auditron\Check;

use Corevitals\Auditron\Domain\CheckResult;
use Symfony\Component\Finder\Finder;

final class ForbiddenFunctionsCheck extends AbstractCheck
{
    private const FORBIDDEN_FUNCTIONS = [
        'exec',
        'system',
        'shell_exec',
        'passthru',
        'popen',
        'proc_open',
        'var_dump',
        'dump',
        'dd',
        'print_r',
        'xdebug_break',
        'ray',
    ];

    public function getName(): string
    {
        return 'Forbidden Debug Functions Analyzer';
    }

    public function getDescription(): string
    {
        return 'Scans the source code for leftover debug statements (e.g., var_dump, dd, die, exit) using native tokenization.';
    }

    public function run(): CheckResult
    {
        $srcPath = getcwd() . DIRECTORY_SEPARATOR . 'src';

        if (!is_dir($srcPath)) {
            return $this->skip(['The "src/" directory does not exist. Static analysis skipped.']);
        }

        $finder = new Finder();
        $finder->files()->in($srcPath)->name('*.php');

        $violations = [];

        foreach ($finder as $file) {
            $contents = $file->getContents();
            $tokens   = token_get_all($contents);
            $filePath = $file->getRelativePathname();

            foreach ($tokens as $index => $token) {
                // Tokens are arrays for actionable code, or single strings for basic characters like '(' or ';'
                if (!is_array($token)) {
                    continue;
                }

                $tokenId   = $token[0];
                $tokenText = strtolower($token[1]);
                $line      = $token[2];

                // Check for die() and exit()
                if ($tokenId === T_EXIT) {
                    $violations[] = sprintf('Found forbidden construct "%s" in %s on line %d.', $token[1], $filePath, $line);
                    continue;
                }

                // Check for debugging function calls
                if ($tokenId === T_STRING && in_array($tokenText, self::FORBIDDEN_FUNCTIONS, true)) {

                    // Look backwards to ensure this isn't a method call (e.g., $this->dump()) or a static call (e.g., Exporter::dump())
                    $isMethodCall = false;
                    $prevIndex    = $index - 1;

                    while ($prevIndex >= 0) {
                        $prevToken = $tokens[$prevIndex];

                        // Ignore whitespace between tokens
                        if (is_array($prevToken) && $prevToken[0] === T_WHITESPACE) {
                            $prevIndex--;
                            continue;
                        }

                        // If preceded by ->, ?->, or ::, it is a method, not a global function
                        if (is_array($prevToken) && in_array($prevToken[0], [T_OBJECT_OPERATOR, T_NULLSAFE_OBJECT_OPERATOR, T_DOUBLE_COLON], true)) {
                            $isMethodCall = true;
                        }

                        break;
                    }

                    if (!$isMethodCall) {
                        $violations[] = sprintf('Found forbidden function "%s" in %s on line %d.', $token[1], $filePath, $line);
                    }
                }
            }
        }

        if (!empty($violations)) {
            return $this->fail($violations);
        }

        return $this->pass(['No forbidden debug functions found in the source code.']);
    }
}
