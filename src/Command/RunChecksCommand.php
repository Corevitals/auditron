<?php

/**
 * Command <<projectversion>>
 * Author: Timothy Lorens (tlorens@corevitals.com)
 * File: RunChecksCommand.php
 * Created: Sunday, June 28th 2026
 * -----
 * Last Modified: Sunday June 28th 2026 3:26 pm
 * Modified By: Timothy Lorens (tlorens@corevitals.com>)
 * -----
 * Copyright 2020 - 2026, CoreVitals, LLC
 */

declare(strict_types=1);

namespace Corevitals\Auditron\Command;

use Corevitals\Auditron\Contract\CheckInterface;
use Corevitals\Auditron\Domain\CheckStatus;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;

#[AsCommand(
    name: 'security:check',
    description: 'Runs the full suite of security and compliance audits.'
)]
final class RunChecksCommand extends Command
{
    /**
     * @param iterable<CheckInterface> $checks
     */
    public function __construct(
        private readonly iterable $checks
    ) {
        parent::__construct();
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $io = new SymfonyStyle($input, $output);
        $io->title('Auditron Security Checker');

        $hasFailures = false;
        $runCount = 0;

        foreach ($this->checks as $check) {
            $runCount++;
            $io->section(sprintf('Check %d: %s', $runCount, $check->getName()));
            $io->text($check->getDescription());

            // Execute the domain logic
            $result = $check->run();

            // Format the output based on the resulting Enum state
            match ($result->status) {
                CheckStatus::PASSED => $io->success('PASSED'),
                CheckStatus::WARNING => $io->warning('WARNING'),
                CheckStatus::SKIPPED => $io->note('SKIPPED'),
                CheckStatus::FAILED => $io->error('FAILED'),
            };

            // Display any contextual messages (e.g., violating files, exact CVEs)
            if (!empty($result->messages)) {
                $io->listing($result->messages);
            }

            // If any check explicitly fails, the entire run will return a failure code
            if (!$result->isSuccessful()) {
                $hasFailures = true;
            }
        }

        if ($runCount === 0) {
            $io->warning('No security checks were registered.');
            return Command::SUCCESS;
        }

        if ($hasFailures) {
            $io->error('Audit complete. One or more security checks failed.');
            return Command::FAILURE;
        }

        $io->success('Audit complete. All security checks passed.');
        return Command::SUCCESS;
    }
}
