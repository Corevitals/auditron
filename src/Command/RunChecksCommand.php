<?php

/**
 * Auditron v1.0.0
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
    name: 'auditron:scan',
    description: 'Runs the full suite of security and compliance audits.'
)]
final class RunChecksCommand extends Command
{
    /** @param iterable<CheckInterface> $checks */
    public function __construct(private readonly iterable $checks) { parent::__construct(); }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $io = new SymfonyStyle($input, $output);
        $io->writeln('Scanning Symfony application...');
        $io->newLine();

        $results = [];
        $stats = ['passed' => 0, 'failed' => 0, 'warning' => 0, 'skipped' => 0];

        foreach ($this->checks as $check) {
            $result    = $check->run();
            $results[] = $result;
            $stats[$result->status->value]++;

            // Print compact status line
            $symbol = $this->getSymbol($result->status);
            $io->writeln(sprintf(' %s %s', $symbol, $check->getName()));
        }

        $io->newLine();
        $io->writeln('Scan completed.');
        $io->newLine();

        // Print Summary
        $io->text(sprintf(
            '%d checks performed | %d warnings | %d critical issues',
            count($results),
            $stats['warning'],
            $stats['failed']
        ));

        // Display failure details at the bottom so they aren't lost
        foreach ($results as $result) {
            if (!$result->isSuccessful() && !empty($result->messages)) {
                $io->section(sprintf('Issue in: %s', $result->checkName));
                $io->listing($result->messages);

                // if ($result->remediation) {
                //     $io->block($result->remediation, 'HOW TO FIX', 'fg=black;bg=yellow', ' ', true);
                // }
            }
        }

        return ($stats['failed'] > 0) ? Command::FAILURE : Command::SUCCESS;
    }

    private function getSymbol(CheckStatus $status): string
    {
        return match ($status) {
            CheckStatus::PASSED  => '<info>✔</info>',
            CheckStatus::WARNING => '<comment>⚠</comment>',
            CheckStatus::FAILED  => '<error>✘</error>',
            CheckStatus::SKIPPED => '<fg=gray>–</>',
        };
    }
}
