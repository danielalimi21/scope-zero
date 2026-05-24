import { randomUUID } from "node:crypto";
import { performance } from "node:perf_hooks";

export class Telemetry {
  constructor({ serviceName = "scopezero-gateway", endpoint = "", headers = "" } = {}) {
    this.serviceName = serviceName;
    this.endpoint = endpoint;
    this.headers = parseHeaders(headers);
    this.spans = [];
  }

  async trace(name, attributes, fn) {
    const span = this.startSpan(name, attributes);
    try {
      const result = await fn(span);
      this.endSpan(span, { status: "ok" });
      return result;
    } catch (error) {
      this.endSpan(span, {
        status: "error",
        "exception.type": error.code || error.name,
        "exception.message": error.message
      });
      throw error;
    }
  }

  startSpan(name, attributes = {}) {
    const span = {
      trace_id: randomUUID().replaceAll("-", ""),
      span_id: randomUUID().replaceAll("-", "").slice(0, 16),
      name,
      service: this.serviceName,
      start_time_unix_nano: String(toUnixNano()),
      start_ms: performance.now(),
      attributes
    };
    this.spans.push(span);
    return span;
  }

  endSpan(span, attributes = {}) {
    span.end_time_unix_nano = String(toUnixNano());
    span.duration_ms = Math.round((performance.now() - span.start_ms) * 100) / 100;
    span.attributes = { ...span.attributes, ...attributes };
    void this.export([span]);
  }

  snapshot({ limit = 50 } = {}) {
    return this.spans.slice(-limit).reverse().map(({ start_ms, ...span }) => span);
  }

  async export(spans) {
    if (!this.endpoint) {
      return;
    }
    const body = JSON.stringify({
      resourceSpans: [
        {
          resource: {
            attributes: [
              { key: "service.name", value: { stringValue: this.serviceName } },
              { key: "deployment.environment", value: { stringValue: process.env.NODE_ENV || "development" } }
            ]
          },
          scopeSpans: [
            {
              scope: { name: "scopezero.runtime", version: "0.1.0" },
              spans: spans.map(toOtlpSpan)
            }
          ]
        }
      ]
    });
    try {
      await fetch(this.endpoint, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          ...this.headers
        },
        body
      });
    } catch {
      // Telemetry must never block authorization decisions.
    }
  }
}

function toOtlpSpan(span) {
  return {
    traceId: span.trace_id,
    spanId: span.span_id,
    name: span.name,
    kind: 2,
    startTimeUnixNano: String(span.start_time_unix_nano),
    endTimeUnixNano: String(span.end_time_unix_nano || toUnixNano()),
    attributes: Object.entries(span.attributes || {}).map(([key, value]) => ({
      key,
      value: otlpValue(value)
    }))
  };
}

function otlpValue(value) {
  if (typeof value === "number") {
    return Number.isInteger(value) ? { intValue: String(value) } : { doubleValue: value };
  }
  if (typeof value === "boolean") {
    return { boolValue: value };
  }
  return { stringValue: String(value ?? "") };
}

function toUnixNano() {
  return BigInt(Date.now()) * 1_000_000n;
}

function parseHeaders(raw) {
  if (!raw) {
    return {};
  }
  return Object.fromEntries(
    raw
      .split(",")
      .map((pair) => pair.trim())
      .filter(Boolean)
      .map((pair) => {
        const [key, ...rest] = pair.split("=");
        return [key.trim(), rest.join("=").trim()];
      })
  );
}
