import test from "node:test";
import assert from "node:assert/strict";
import {
  analyzeToolCallBehavior,
  createEmptyProfile,
  updateBehaviorProfile
} from "../src/behaviorAnalyzer.js";

function makeProfile(tenantId, agentId) {
  return createEmptyProfile(tenantId, agentId);
}

function isoAt(offsetMs, base = new Date()) {
  return new Date(base.getTime() + offsetMs).toISOString();
}

// Builds a profile with N historical calls spread over 10 hours starting from `base`
function buildEstablishedProfile(tenantId, agentId, toolKey, n, base = new Date()) {
  const profile = makeProfile(tenantId, agentId);
  const stepMs = (10 * 60 * 60 * 1000) / Math.max(1, n);
  for (let i = 0; i < n; i++) {
    const t = new Date(base.getTime() - (10 * 60 * 60 * 1000) + i * stepMs);
    updateBehaviorProfile(profile, toolKey, t);
  }
  return profile;
}

test("new tool first use is flagged as low severity", () => {
  const profile = makeProfile("t1", "a1");
  const { anomalies, risk_delta } = analyzeToolCallBehavior(profile, "gmail.send", new Date());
  assert.equal(anomalies.length, 1);
  assert.equal(anomalies[0].code, "new_tool_first_use");
  assert.equal(anomalies[0].severity, "low");
  assert.ok(risk_delta > 0);
});

test("established profile with normal usage has no burst or velocity anomalies", () => {
  const now = new Date();
  // 30 calls evenly spread over 10 hours — no clustering in recent windows
  const profile = makeProfile("t1", "a1");
  const stepMs = (10 * 60 * 60 * 1000) / 30;
  for (let i = 0; i < 30; i++) {
    const t = new Date(now.getTime() - (10 * 60 * 60 * 1000) + i * stepMs);
    updateBehaviorProfile(profile, "drive.search", t);
  }
  const { anomalies } = analyzeToolCallBehavior(profile, "drive.search", now);
  assert.ok(!anomalies.find(a => a.code === "burst_absolute"), "no burst expected");
  assert.ok(!anomalies.find(a => a.code === "velocity_spike"), "no velocity spike expected");
});

test("burst absolute fires when 10+ calls in 5 minutes", () => {
  const now = new Date();
  const profile = makeProfile("t1", "a1");
  // One old call to establish tool history
  updateBehaviorProfile(profile, "gmail.send", new Date(now.getTime() - 2 * 60 * 60 * 1000));
  // 10 calls in last 3 minutes
  for (let i = 0; i < 10; i++) {
    updateBehaviorProfile(profile, "gmail.send", new Date(now.getTime() - (3 * 60 * 1000) + i * 10000));
  }
  const { anomalies } = analyzeToolCallBehavior(profile, "gmail.send", now);
  const burst = anomalies.find(a => a.code === "burst_absolute");
  assert.ok(burst, "burst_absolute anomaly expected");
  assert.equal(burst.severity, "high");
  assert.ok(burst.observed_rate >= 10);
});

test("burst absolute does not fire for 9 calls in 5 minutes", () => {
  const now = new Date();
  const profile = makeProfile("t1", "a1");
  updateBehaviorProfile(profile, "gmail.send", new Date(now.getTime() - 2 * 60 * 60 * 1000));
  for (let i = 0; i < 9; i++) {
    updateBehaviorProfile(profile, "gmail.send", new Date(now.getTime() - (3 * 60 * 1000) + i * 10000));
  }
  const { anomalies } = analyzeToolCallBehavior(profile, "gmail.send", now);
  assert.ok(!anomalies.find(a => a.code === "burst_absolute"));
});

test("velocity spike fires when hourly rate far exceeds baseline", () => {
  const now = new Date();
  // Build baseline: 20 calls over 10 hours → ~2/hr average
  const profile = buildEstablishedProfile("t1", "a1", "slack.post", 20, now);
  // Now jam 20 calls into the last 60 minutes (10x baseline)
  for (let i = 0; i < 20; i++) {
    updateBehaviorProfile(profile, "slack.post", new Date(now.getTime() - (50 * 60 * 1000) + i * 30000));
  }
  const { anomalies } = analyzeToolCallBehavior(profile, "slack.post", now);
  const spike = anomalies.find(a => a.code === "velocity_spike");
  assert.ok(spike, "velocity_spike anomaly expected");
  assert.equal(spike.severity, "high");
  assert.ok(spike.observed_rate >= 20);
});

test("velocity spike does not fire when profile too young", () => {
  const now = new Date();
  // Only 3 hours of history — below BASELINE_MIN_AGE_HOURS=5
  const profile = makeProfile("t1", "a1");
  const stepMs = (3 * 60 * 60 * 1000) / 20;
  for (let i = 0; i < 20; i++) {
    updateBehaviorProfile(profile, "slack.post", new Date(now.getTime() - (3 * 60 * 60 * 1000) + i * stepMs));
  }
  // 20 calls in last 60 min should NOT fire velocity spike due to young profile
  for (let i = 0; i < 20; i++) {
    updateBehaviorProfile(profile, "slack.post", new Date(now.getTime() - (50 * 60 * 1000) + i * 30000));
  }
  const { anomalies } = analyzeToolCallBehavior(profile, "slack.post", now);
  assert.ok(!anomalies.find(a => a.code === "velocity_spike"));
});

test("off hours activity fires when call at previously unseen hour", () => {
  const now = new Date();
  const profile = makeProfile("t1", "a1");
  const targetHour = now.getUTCHours();
  const otherHour = (targetHour + 12) % 24;
  // 25 calls all at a different hour
  for (let i = 0; i < 25; i++) {
    const t = new Date(now.getTime() - (i + 1) * 60 * 60 * 1000);
    t.setUTCHours(otherHour);
    updateBehaviorProfile(profile, "drive.read", t);
  }
  const { anomalies } = analyzeToolCallBehavior(profile, "drive.read", now);
  const offHours = anomalies.find(a => a.code === "off_hours_activity");
  assert.ok(offHours, "off_hours_activity anomaly expected");
  assert.equal(offHours.severity, "medium");
});

test("off hours does not fire when profile below minimum calls", () => {
  const now = new Date();
  const profile = makeProfile("t1", "a1");
  const otherHour = (now.getUTCHours() + 12) % 24;
  for (let i = 0; i < 15; i++) {
    const t = new Date(now.getTime() - (i + 1) * 60 * 60 * 1000);
    t.setUTCHours(otherHour);
    updateBehaviorProfile(profile, "drive.read", t);
  }
  const { anomalies } = analyzeToolCallBehavior(profile, "drive.read", now);
  assert.ok(!anomalies.find(a => a.code === "off_hours_activity"));
});

test("updateBehaviorProfile increments counters and records hourly distribution", () => {
  const profile = makeProfile("t1", "a1");
  const t = new Date("2025-06-01T14:30:00Z");
  updateBehaviorProfile(profile, "slack.send", t);
  const tp = profile.tools["slack.send"];
  assert.equal(tp.total_calls, 1);
  assert.equal(tp.hourly_dist[14], 1);
  assert.equal(tp.velocity_window.length, 1);
  assert.equal(tp.velocity_window[0], t.toISOString());
});

test("updateBehaviorProfile trims velocity window to 200 entries", () => {
  const profile = makeProfile("t1", "a1");
  const base = new Date();
  for (let i = 0; i < 220; i++) {
    updateBehaviorProfile(profile, "aws.s3.get", new Date(base.getTime() - i * 1000));
  }
  assert.equal(profile.tools["aws.s3.get"].velocity_window.length, 200);
  assert.equal(profile.tools["aws.s3.get"].total_calls, 220);
});

// Cold-start detection (calls 1–19)

test("cold start observation fires on second call to any tool", () => {
  const now = new Date();
  const profile = makeProfile("t1", "a1");
  updateBehaviorProfile(profile, "drive.read", new Date(now.getTime() - 60000));
  const { anomalies } = analyzeToolCallBehavior(profile, "drive.read", now);
  const cs = anomalies.find(a => a.code === "cold_start_observation");
  assert.ok(cs, "cold_start_observation expected");
  assert.equal(cs.calls_recorded, 1);
});

test("cold start is medium severity for low-risk tools", () => {
  const now = new Date();
  const profile = makeProfile("t1", "a1");
  updateBehaviorProfile(profile, "drive.read", new Date(now.getTime() - 60000));
  const { anomalies } = analyzeToolCallBehavior(profile, "drive.read", now);
  const cs = anomalies.find(a => a.code === "cold_start_observation");
  assert.equal(cs.severity, "medium");
});

test("cold start is high severity for high-risk tools like gmail.send", () => {
  const now = new Date();
  const profile = makeProfile("t1", "a1");
  updateBehaviorProfile(profile, "gmail.send", new Date(now.getTime() - 60000));
  const { anomalies } = analyzeToolCallBehavior(profile, "gmail.send", now);
  const cs = anomalies.find(a => a.code === "cold_start_observation");
  assert.equal(cs.severity, "high");
});

test("cold start is high severity for export tools", () => {
  const now = new Date();
  const profile = makeProfile("t1", "a1");
  updateBehaviorProfile(profile, "data.export", new Date(now.getTime() - 60000));
  const { anomalies } = analyzeToolCallBehavior(profile, "data.export", now);
  const cs = anomalies.find(a => a.code === "cold_start_observation");
  assert.equal(cs.severity, "high");
});

test("cold start does not fire once baseline is reached", () => {
  const now = new Date();
  const profile = buildEstablishedProfile("t1", "a1", "drive.read", 20, now);
  const { anomalies } = analyzeToolCallBehavior(profile, "drive.read", now);
  assert.ok(!anomalies.find(a => a.code === "cold_start_observation"));
});

test("burst still fires during cold start phase", () => {
  const now = new Date();
  const profile = makeProfile("t1", "a1");
  // 1 old call to get past total_calls === 0
  updateBehaviorProfile(profile, "gmail.send", new Date(now.getTime() - 2 * 60 * 60 * 1000));
  // 10 rapid calls — total_calls goes to 11 (< 20, still cold start)
  for (let i = 0; i < 10; i++) {
    updateBehaviorProfile(profile, "gmail.send", new Date(now.getTime() - (4 * 60 * 1000) + i * 20000));
  }
  const { anomalies } = analyzeToolCallBehavior(profile, "gmail.send", now);
  assert.ok(anomalies.find(a => a.code === "burst_absolute"), "burst should still fire in cold start");
  assert.ok(anomalies.find(a => a.code === "cold_start_observation"), "cold start should also be present");
});
