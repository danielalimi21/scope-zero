const VELOCITY_WINDOW_MAX = 200;
const BURST_WINDOW_MS = 5 * 60 * 1000;      // 5 minutes
const BURST_THRESHOLD = 10;                  // calls in BURST_WINDOW_MS
const HOURLY_WINDOW_MS = 60 * 60 * 1000;    // 1 hour
const BASELINE_MIN_CALLS = 20;              // profile considered established
const BASELINE_MIN_AGE_HOURS = 5;           // hours of history before velocity checks
const VELOCITY_SPIKE_MULTIPLIER = 3;        // observed rate / baseline rate to flag
const VELOCITY_SPIKE_FLOOR = 5;             // minimum threshold regardless of baseline

// Tools whose first uses warrant escalation even before baseline is established.
// Pattern matches the tool key (e.g. "gmail.send", "aws.iam.attachPolicy").
const HIGH_RISK_COLD_START = /send|email|publish|share|export|delete|drop|iam|policy|permission|payment|transfer|wire/i;

export function createEmptyProfile(tenantId, agentId) {
  return { tenant_id: tenantId, agent_id: agentId, tools: {} };
}

export function createEmptyToolProfile(now) {
  return {
    total_calls: 0,
    first_seen: now.toISOString(),
    last_seen: now.toISOString(),
    hourly_dist: Array(24).fill(0),
    velocity_window: []
  };
}

// Analyze behavior BEFORE recording the current call.
// Returns { anomalies: [], risk_delta: number }
export function analyzeToolCallBehavior(profile, toolKey, now = new Date()) {
  const toolProfile = profile?.tools?.[toolKey];

  if (!toolProfile || toolProfile.total_calls === 0) {
    return {
      anomalies: [{
        code: "new_tool_first_use",
        message: `Agent has no prior history with tool ${toolKey}.`,
        severity: "low",
        risk_delta: 5
      }],
      risk_delta: 5
    };
  }

  const anomalies = [];

  // Cold-start window: calls 1–19. Baseline not yet established.
  // Does NOT return early — burst check still runs below.
  if (toolProfile.total_calls < BASELINE_MIN_CALLS) {
    const isHighRisk = HIGH_RISK_COLD_START.test(toolKey);
    anomalies.push({
      code: "cold_start_observation",
      message: `Tool ${toolKey} has only ${toolProfile.total_calls} recorded calls — baseline not yet established (need ${BASELINE_MIN_CALLS}).`,
      severity: isHighRisk ? "high" : "medium",
      risk_delta: isHighRisk ? 25 : 10,
      calls_recorded: toolProfile.total_calls,
      calls_until_baseline: BASELINE_MIN_CALLS - toolProfile.total_calls
    });
  }
  const hour = now.getUTCHours();

  if (toolProfile.total_calls >= BASELINE_MIN_CALLS) {
    const hourCount = toolProfile.hourly_dist[hour] || 0;
    if (hourCount === 0) {
      anomalies.push({
        code: "off_hours_activity",
        message: `Tool ${toolKey} has never been used at UTC hour ${hour} in ${toolProfile.total_calls} historical calls.`,
        severity: "medium",
        risk_delta: 15
      });
    }
  }

  const burstCutoff = new Date(now.getTime() - BURST_WINDOW_MS);
  const recentBurst = (toolProfile.velocity_window || [])
    .filter(ts => new Date(ts) >= burstCutoff).length;

  if (recentBurst >= BURST_THRESHOLD) {
    anomalies.push({
      code: "burst_absolute",
      message: `${recentBurst} calls to ${toolKey} in the last 5 minutes.`,
      severity: "high",
      risk_delta: 40,
      observed_rate: recentBurst
    });
  }

  const firstSeenMs = toolProfile.first_seen ? new Date(toolProfile.first_seen).getTime() : null;
  const ageHours = firstSeenMs ? (now.getTime() - firstSeenMs) / HOURLY_WINDOW_MS : 0;
  const alreadyBurst = recentBurst >= BURST_THRESHOLD;

  if (!alreadyBurst && ageHours >= BASELINE_MIN_AGE_HOURS && toolProfile.total_calls >= BASELINE_MIN_CALLS) {
    const hourlyCutoff = new Date(now.getTime() - HOURLY_WINDOW_MS);
    const recentHourly = (toolProfile.velocity_window || [])
      .filter(ts => new Date(ts) >= hourlyCutoff).length;
    const meanHourlyRate = toolProfile.total_calls / ageHours;
    const spikeThreshold = Math.max(VELOCITY_SPIKE_FLOOR, meanHourlyRate * VELOCITY_SPIKE_MULTIPLIER);

    if (recentHourly > spikeThreshold) {
      anomalies.push({
        code: "velocity_spike",
        message: `${recentHourly} calls to ${toolKey} in the last 60 minutes; baseline avg is ${meanHourlyRate.toFixed(1)}/hr.`,
        severity: "high",
        risk_delta: 30,
        observed_rate: recentHourly,
        baseline_rate: Math.round(meanHourlyRate * 10) / 10
      });
    }
  }

  const risk_delta = anomalies.reduce((sum, a) => sum + a.risk_delta, 0);
  return { anomalies, risk_delta };
}

// Mutates profile in-place. Call AFTER analyzeToolCallBehavior.
export function updateBehaviorProfile(profile, toolKey, now = new Date()) {
  if (!profile.tools) profile.tools = {};
  if (!profile.tools[toolKey]) {
    profile.tools[toolKey] = createEmptyToolProfile(now);
  }
  const tp = profile.tools[toolKey];
  tp.total_calls += 1;
  tp.last_seen = now.toISOString();
  tp.hourly_dist[now.getUTCHours()] += 1;
  tp.velocity_window.push(now.toISOString());
  if (tp.velocity_window.length > VELOCITY_WINDOW_MAX) {
    tp.velocity_window = tp.velocity_window.slice(-VELOCITY_WINDOW_MAX);
  }
  return profile;
}
