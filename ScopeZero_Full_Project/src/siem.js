export function exportEvents(events, format = "json") {
  if (format === "cef") {
    return events.map(toCef).join("\n") + "\n";
  }
  if (format === "leef") {
    return events.map(toLeef).join("\n") + "\n";
  }
  if (format === "otlp") {
    return toOtlpLogs(events);
  }
  return {
    schema: "scopezero.siem.events.v1",
    events: events.map(toJsonEvent)
  };
}

export function contentTypeForSiem(format) {
  if (format === "cef" || format === "leef") {
    return "text/plain; charset=utf-8";
  }
  return "application/json";
}

function toJsonEvent(entry) {
  const record = entry.record || {};
  const verdict = record.verdict || {};
  return {
    time: entry.time,
    event_id: entry.id,
    event_hash: entry.hash,
    previous_hash: entry.previous_hash,
    event_type: record.event_type,
    tenant_id: record.tenant_id || record.agent?.tenant_id || record.mission?.tenant_id || record.approval?.tenant_id,
    agent_id: record.agent_id || record.agent?.agent_id || record.mission?.agent_id || record.approval?.agent_id,
    mission_id: record.mission_id || record.mission?.id || record.approval?.mission_id,
    tool: record.tool || record.approval?.tool,
    action: record.action || record.approval?.action,
    decision: verdict.decision,
    severity: verdict.severity,
    risk_score: verdict.risk_score,
    reason_codes: verdict.reasons?.map((reason) => reason.code) || []
  };
}

function toCef(entry) {
  const event = toJsonEvent(entry);
  const severity = cefSeverity(event.severity);
  return [
    "CEF:0",
    "ScopeZero",
    "ScopeZero Gateway",
    "0.1.0",
    event.event_type || "scopezero.event",
    event.decision || event.event_type || "runtime_event",
    severity
  ].join("|") + "|" + extension({
    rt: event.time,
    cs1Label: "tenant_id",
    cs1: event.tenant_id,
    cs2Label: "agent_id",
    cs2: event.agent_id,
    cs3Label: "mission_id",
    cs3: event.mission_id,
    cs4Label: "tool",
    cs4: event.tool,
    act: event.decision,
    cn1Label: "risk_score",
    cn1: event.risk_score,
    externalId: event.event_hash
  });
}

function toLeef(entry) {
  const event = toJsonEvent(entry);
  return [
    "LEEF:2.0|ScopeZero|ScopeZero Gateway|0.1.0|" + (event.event_type || "scopezero.event"),
    kv({
      devTime: event.time,
      tenant: event.tenant_id,
      agent: event.agent_id,
      mission: event.mission_id,
      tool: event.tool,
      action: event.action,
      decision: event.decision,
      severity: event.severity,
      risk: event.risk_score,
      hash: event.event_hash
    }, "\t")
  ].join("\t");
}

function toOtlpLogs(events) {
  return {
    resourceLogs: [
      {
        resource: {
          attributes: [
            { key: "service.name", value: { stringValue: "scopezero-gateway" } },
            { key: "service.version", value: { stringValue: "0.1.0" } }
          ]
        },
        scopeLogs: [
          {
            scope: { name: "scopezero.siem", version: "0.1.0" },
            logRecords: events.map((entry) => {
              const event = toJsonEvent(entry);
              return {
                timeUnixNano: String(new Date(entry.time).getTime() * 1_000_000),
                severityText: String(event.severity || "INFO").toUpperCase(),
                body: { stringValue: JSON.stringify(event) },
                attributes: Object.entries({
                  "scopezero.event_id": event.event_id,
                  "scopezero.event_hash": event.event_hash,
                  "scopezero.tenant_id": event.tenant_id,
                  "scopezero.agent_id": event.agent_id,
                  "scopezero.mission_id": event.mission_id,
                  "scopezero.tool": event.tool,
                  "scopezero.decision": event.decision,
                  "scopezero.risk_score": event.risk_score
                })
                  .filter(([, value]) => value !== undefined && value !== null)
                  .map(([key, value]) => ({ key, value: { stringValue: String(value) } }))
              };
            })
          }
        ]
      }
    ]
  };
}

function extension(fields) {
  return Object.entries(fields)
    .filter(([, value]) => value !== undefined && value !== null)
    .map(([key, value]) => `${key}=${escapeCef(String(value))}`)
    .join(" ");
}

function kv(fields, separator) {
  return Object.entries(fields)
    .filter(([, value]) => value !== undefined && value !== null)
    .map(([key, value]) => `${key}=${String(value).replace(/\t/g, " ")}`)
    .join(separator);
}

function escapeCef(value) {
  return value.replace(/\\/g, "\\\\").replace(/\|/g, "\\|").replace(/=/g, "\\=").replace(/\n/g, "\\n");
}

function cefSeverity(severity) {
  return {
    low: 3,
    medium: 5,
    high: 8,
    critical: 10
  }[severity] || 4;
}
