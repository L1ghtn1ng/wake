"""Wake's bounded, per-process metrics in Flasgo's protected registry."""

from prometheus_client import CollectorRegistry, Counter, Gauge, Histogram


class WakeMetrics:
    """Register once during app setup; record observations where work happens."""

    def __init__(self, registry: CollectorRegistry) -> None:
        self.wake_packets = Counter(
            'wake_packets_total',
            'Wake-on-LAN packet send attempts by outcome; success means the send call returned.',
            ['outcome'],
            registry=registry,
        )
        self.probes = Counter(
            'wake_probes_total',
            'Executed status probes by type and outcome; excludes cache hits and disabled probes.',
            ['type', 'outcome'],
            registry=registry,
        )
        self.probe_duration = Histogram(
            'wake_probe_duration_seconds',
            'Elapsed status probe time including failures and cancellations.',
            ['type'],
            buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30),
            registry=registry,
        )
        self.ssh_sessions = Counter(
            'wake_ssh_sessions_total',
            'Finished SSH session attempts after terminal authorization and slot reservation, by outcome.',
            ['outcome'],
            registry=registry,
        )
        self.ssh_active = Gauge(
            'wake_ssh_sessions_active',
            'Reserved terminal sessions, including SSH connection setup.',
            registry=registry,
        )
        self.ssh_duration = Histogram(
            'wake_ssh_session_duration_seconds',
            'Elapsed time from terminal slot reservation to session cleanup.',
            buckets=(0.1, 0.5, 1, 5, 10, 30, 60, 300, 600, 1800),
            registry=registry,
        )
