const STATE_NUMERIC_MAP = {
    Stopped: 0,
    Running: 1,
    Degraded: 2,
    Failed: 3,
    Paused: 4,
    Initializing: 5,
    Stopping: 6,
    Restarting: 7,
};
export function generatePrometheusMetrics(collectors) {
    const lines = [];
    lines.push('# HELP soc_collector_status Collector operational status (0=Stopped, 1=Running, 2=Degraded, 3=Failed, 4=Paused)');
    lines.push('# TYPE soc_collector_status gauge');
    lines.push('# HELP soc_collector_events_processed_total Total count of telemetry events processed');
    lines.push('# TYPE soc_collector_events_processed_total counter');
    lines.push('# HELP soc_collector_events_per_second Current rolling events processed per second');
    lines.push('# TYPE soc_collector_events_per_second gauge');
    lines.push('# HELP soc_collector_dropped_packets_total Total count of dropped telemetry packets');
    lines.push('# TYPE soc_collector_dropped_packets_total counter');
    lines.push('# HELP soc_collector_queue_depth Current depth of ingestion ring buffer queue');
    lines.push('# TYPE soc_collector_queue_depth gauge');
    lines.push('# HELP soc_collector_average_latency_ms Average parsing and pipeline ingestion latency in milliseconds');
    lines.push('# TYPE soc_collector_average_latency_ms gauge');
    for (const collector of collectors) {
        const metrics = collector.getMetrics();
        const stateVal = STATE_NUMERIC_MAP[metrics.state] ?? 0;
        lines.push(`soc_collector_status{collector="${collector.name}",type="${collector.type}"} ${stateVal}`);
        lines.push(`soc_collector_events_processed_total{collector="${collector.name}",type="${collector.type}"} ${metrics.eventsProcessedTotal}`);
        lines.push(`soc_collector_events_per_second{collector="${collector.name}",type="${collector.type}"} ${metrics.eventsPerSecond}`);
        lines.push(`soc_collector_dropped_packets_total{collector="${collector.name}",type="${collector.type}",reason="rate_limited"} ${metrics.droppedReasonBreakdown.rateLimited}`);
        lines.push(`soc_collector_dropped_packets_total{collector="${collector.name}",type="${collector.type}",reason="backpressure"} ${metrics.droppedReasonBreakdown.backpressureEvicted}`);
        lines.push(`soc_collector_dropped_packets_total{collector="${collector.name}",type="${collector.type}",reason="malformed"} ${metrics.droppedReasonBreakdown.malformed}`);
        lines.push(`soc_collector_queue_depth{collector="${collector.name}",type="${collector.type}"} ${metrics.queueDepth}`);
        lines.push(`soc_collector_average_latency_ms{collector="${collector.name}",type="${collector.type}"} ${metrics.averageLatencyMs}`);
    }
    return lines.join('\n') + '\n';
}
