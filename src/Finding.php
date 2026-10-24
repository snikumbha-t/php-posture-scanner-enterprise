<?php
declare(strict_types=1);

namespace PvC;

final class Finding
{
    public const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info', 'good'];
    public const WEIGHT = [
        'critical' => 40, 'high' => 20, 'medium' => 10, 'low' => 4, 'info' => 0, 'good' => 0,
    ];

    public function __construct(
        public string $id,
        public string $severity,
        public string $title,
        public string $detail,
        public string $recommendation = '',
        public string $evidence = '',
        public string $category = 'General',
    ) {}

    public function weight(): int
    {
        return self::WEIGHT[$this->severity] ?? 0;
    }

    public function toArray(): array
    {
        return [
            'id' => $this->id,
            'severity' => $this->severity,
            'title' => $this->title,
            'detail' => $this->detail,
            'recommendation' => $this->recommendation,
            'evidence' => $this->evidence,
            'category' => $this->category,
        ];
    }
}
