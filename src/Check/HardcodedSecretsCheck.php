<?php

/**
 * Auditron v1.0.0
 * Author: Timothy Lorens (tlorens@corevitals.com)
 * File: HardcodedSecretsCheck.php
 * Created: Sunday, June 28th 2026
 * -----
 * Last Modified: Sunday June 28th 2026 4:10 pm
 * Modified By: Timothy Lorens (tlorens@corevitals.com>)
 * -----
 * Copyright 2020 - 2026, CoreVitals, LLC
 */

declare(strict_types=1);

namespace Corevitals\Auditron\Check;

use Corevitals\Auditron\Domain\CheckResult;
use Symfony\Component\Finder\Finder;

final class HardcodedSecretsCheck extends AbstractCheck
{
    /**
     * A list of substrings that strongly suggest a variable or key holds sensitive data.
     */
    private const SUSPICIOUS_IDENTIFIERS = [
        'password',
        'secret',
        'api_key',
        'apikey',
        'csrf',
        'nonce',
        'salt',
        'otp',
        'passphrase',
        'private_key',
        'public_key',
        'access_token',
        'token',
        'credential',
        'auth_token'
    ];

    public function getName(): string
    {
        return 'Hardcoded Secrets Analyzer';
    }

    public function getDescription(): string
    {
        return 'Scans the source code for sensitive variables or array keys assigned to static string literals.';
    }

    public function run(): CheckResult
    {
        $srcPath = getcwd() . DIRECTORY_SEPARATOR . 'src';

        if (!is_dir($srcPath)) {
            return $this->skip(['The "src/" directory does not exist. Secrets analysis skipped.']);
        }

        $finder = new Finder();
        $finder->files()->in($srcPath)->name('*.php');

        $violations = [];

        foreach ($finder as $file) {
            $contents   = $file->getContents();
            $tokens     = token_get_all($contents);
            $filePath   = $file->getRelativePathname();
            $tokenCount = count($tokens);

            for ($i = 0; $i < $tokenCount; $i++) {
                $token = $tokens[$i];

                if (!is_array($token)) {
                    continue;
                }

                $tokenId   = $token[0];
                $tokenText = strtolower($token[1]);
                $line      = $token[2];

                $isSuspicious = false;

                // Check if the current token is a suspicious Variable (e.g., $apiKey)
                if ($tokenId === T_VARIABLE && $this->isSuspiciousIdentifier($tokenText)) {
                    $isSuspicious = true;
                }
                // Check if the current token is a suspicious Array Key (e.g., 'api_secret')
                elseif ($tokenId === T_CONSTANT_ENCAPSED_STRING && $this->isSuspiciousIdentifier(trim($tokenText, "'\""))) {
                    $isSuspicious = true;
                }

                if ($isSuspicious) {
                    // Look ahead to see if it is being assigned a hardcoded string literal
                    $lookahead = $this->findAssignedStringLiteral($tokens, $i, $tokenCount);

                    if ($lookahead !== null) {
                        // Ignore empty strings or very short placeholders like 'xxx'
                        if (strlen(trim($lookahead, "'\"")) > 4) {
                            $violations[] = sprintf(
                                'Potential hardcoded secret assigned to "%s" in %s on line %d.',
                                $token[1],
                                $filePath,
                                $line
                            );
                        }
                    }
                }
            }
        }

        if (!empty($violations)) {
            return $this->fail($violations);
        }

        return $this->pass(['No hardcoded secrets detected in the source code.']);
    }

    /**
     * Determines if the variable or key name contains any of the suspicious keywords.
     */
    private function isSuspiciousIdentifier(string $identifier): bool
    {
        foreach (self::SUSPICIOUS_IDENTIFIERS as $suspicious) {
            if (str_contains($identifier, $suspicious)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Scans forward from the current token, ignoring whitespace, to see if the
     * next meaningful tokens are an assignment (= or =>) followed by a string literal.
     */
    private function findAssignedStringLiteral(array $tokens, int $currentIndex, int $totalTokens): ?string
    {
        $operatorFound = false;

        for ($j = $currentIndex + 1; $j < $totalTokens; $j++) {
            $nextToken = $tokens[$j];

            // Ignore whitespace and comments
            if (is_array($nextToken) && in_array($nextToken[0], [T_WHITESPACE, T_COMMENT, T_DOC_COMMENT], true)) {
                continue;
            }

            // We are looking for '=' or T_DOUBLE_ARROW ('=>')
            if (!$operatorFound) {
                if ($nextToken === '=' || (is_array($nextToken) && $nextToken[0] === T_DOUBLE_ARROW)) {
                    $operatorFound = true;
                    continue;
                }

                // If the very next meaningful token isn't an assignment operator, break out.
                return null;
            }

            // Operator was found. We are now looking for the assigned value.
            if ($operatorFound) {
                if (is_array($nextToken) && $nextToken[0] === T_CONSTANT_ENCAPSED_STRING) {
                    return $nextToken[1];
                }

                // If it's assigned to anything other than a string literal (e.g., a function call, another variable), it's safe.
                return null;
            }
        }

        return null;
    }
}
