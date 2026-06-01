const canvas = document.getElementById("heroCanvas");
const ctx = canvas.getContext("2d");
let width = 0;
let height = 0;
let dpr = 1;
let particles = [];

function resizeCanvas() {
  dpr = Math.min(window.devicePixelRatio || 1, 2);
  width = window.innerWidth;
  height = window.innerHeight;
  canvas.width = Math.floor(width * dpr);
  canvas.height = Math.floor(height * dpr);
  canvas.style.width = `${width}px`;
  canvas.style.height = `${height}px`;
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  particles = Array.from({ length: Math.min(72, Math.max(34, Math.floor(width / 18))) }, () => ({
    x: Math.random() * width,
    y: Math.random() * height,
    vx: (Math.random() - 0.5) * 0.26,
    vy: (Math.random() - 0.5) * 0.22,
    r: Math.random() * 2 + 0.7,
    hue: Math.random() > 0.55 ? "86,240,170" : "116,216,255"
  }));
}

function drawCanvas() {
  ctx.clearRect(0, 0, width, height);
  const scroll = window.scrollY || 0;
  const drift = scroll * 0.018;

  for (const p of particles) {
    p.x += p.vx;
    p.y += p.vy;
    if (p.x < -20) p.x = width + 20;
    if (p.x > width + 20) p.x = -20;
    if (p.y < -20) p.y = height + 20;
    if (p.y > height + 20) p.y = -20;
  }

  for (let i = 0; i < particles.length; i += 1) {
    const a = particles[i];
    for (let j = i + 1; j < particles.length; j += 1) {
      const b = particles[j];
      const dx = a.x - b.x;
      const dy = a.y - b.y;
      const distance = Math.sqrt(dx * dx + dy * dy);
      if (distance < 128) {
        ctx.strokeStyle = `rgba(214,242,234,${(1 - distance / 128) * 0.13})`;
        ctx.lineWidth = 1;
        ctx.beginPath();
        ctx.moveTo(a.x, a.y + drift);
        ctx.lineTo(b.x, b.y + drift);
        ctx.stroke();
      }
    }
  }

  for (const p of particles) {
    ctx.fillStyle = `rgba(${p.hue},0.58)`;
    ctx.beginPath();
    ctx.arc(p.x, p.y + drift, p.r, 0, Math.PI * 2);
    ctx.fill();
  }

  requestAnimationFrame(drawCanvas);
}

function revealOnScroll() {
  const observer = new IntersectionObserver((entries) => {
    for (const entry of entries) {
      if (entry.isIntersecting) {
        entry.target.classList.add("visible");
        observer.unobserve(entry.target);
      }
    }
  }, { threshold: 0.16 });

  document.querySelectorAll("[data-reveal]").forEach((element) => observer.observe(element));
}

window.addEventListener("resize", resizeCanvas);
resizeCanvas();
drawCanvas();
revealOnScroll();
