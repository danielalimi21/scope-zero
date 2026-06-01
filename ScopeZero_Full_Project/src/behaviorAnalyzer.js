const VELOCITY_WINDOW_MAX = 200;
const BURST_WINDOW_MS = 5 * 60 * 1000;      // 5 minutes
const BURST_THRESHOLD = 10;                  // calls in BURST_WINDOW_MS
const HOURLY_WINDOW_MS = 60 * 60 * 1000;    // 1 hour
const BASELINE_MIN_CALLS = 20;              // profile considered established
const BASELINE_MIN_AGE_HOURS = 5;           // hours of history before velocity checks
const VELOCITY_SPIKE_MULTIPLIER = 3;        // observed rate / baseline rate to flag
const VELOCITY_SPIKE_FLOOR = 5;             // minimum threshold regardless of baseline
// Absolute rolling-day ceilings, independent of the learned baseline. Velocity
// checks are baseline-relative, so an attacker who either drips calls slowly
// (under the burst/spike thresholds) or first inflates the baseline can sustain
// abuse indefinitely. A baseline-independent daily ceiling closes that gap.
const DAILY_VOLUME_CAP = 500;               // low-risk tools, calls per UTC day
const DAILY_VOLUME_CAP_HIGH_RISK = 50;      // high-risk tools, calls per UTC day
const DAILY_COUNTS_RETENTION_DAYS = 7;

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
    velocity_window: [],
    daily_counts: {}
  };
}

function dayKey(date) {
  return date.toISOString().slice(0, 10);
}

// Analyze behavior BEFORE recording the current call.
// Returns { anomalies: [], risk_delta: number }
export function analyzeToolCallBehavior(profile, toolKey, now = new Date(), options = {}) {
  const toolProfile = profile?.tools?.[toolKey];
  const dailyCap = Number(options.dailyVolumeCap ?? DAILY_VOLUME_CAP);
  const dailyCapHighRisk = Number(options.dailyVolumeCapHighRisk ?? DAILY_VOLUME_CAP_HIGH_RISK);

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

  // Absolute daily ceiling — catches low-and-slow campaigns that stay under the
  // burst/velocity thresholds, and baseline-poisoning (you cannot inflate an
  // absolute cap). Counts prior calls today; this call is the one that crosses.
  const isHighRiskTool = HIGH_RISK_COLD_START.test(toolKey);
  const dayCap = isHighRiskTool ? dailyCapHighRisk : dailyCap;
  const todayCount = (toolProfile.daily_counts || {})[dayKey(now)] || 0;
  if (dayCap > 0 && todayCount >= dayCap) {
    anomalies.push({
      code: "sustained_volume",
      message: `${todayCount + 1} calls to ${toolKey} today exceeds the daily ceiling of ${dayCap} (baseline-independent).`,
      severity: "high",
      risk_delta: 35,
      observed_today: todayCount + 1,
      daily_cap: dayCap
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
  if (!tp.daily_counts) tp.daily_counts = {};
  const key = dayKey(now);
  tp.daily_counts[key] = (tp.daily_counts[key] || 0) + 1;
  pruneDailyCounts(tp, now);
  return profile;
}

function pruneDailyCounts(toolProfile, now) {
  const cutoff = new Date(now.getTime() - DAILY_COUNTS_RETENTION_DAYS * 24 * 60 * 60 * 1000);
  for (const key of Object.keys(toolProfile.daily_counts)) {
    if (new Date(`${key}T00:00:00Z`) < cutoff) {
      delete toolProfile.daily_counts[key];
    }
  }
}
