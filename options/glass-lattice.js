(() => {
  const VERTEX = `#version 300 es
in vec2 position;
void main() {
  gl_Position = vec4(position, 0.0, 1.0);
}
`;

  const FRAGMENT = `#version 300 es
precision highp float;
uniform vec2 iResolution;
uniform float iTime;
uniform float uSpeed;
uniform float uWaveDepth;
uniform float uZoom;
uniform float uDensity;
uniform float uSpread;
uniform float uStepSize;
uniform float uGlow;
uniform float uExposure;
uniform float uColorShift;
uniform float uContrast;
uniform float uBrightness;
uniform float uOpacity;
uniform float uSteps;
uniform vec3 uColor1;
uniform vec3 uColor2;
uniform vec3 uColor3;
uniform vec2 uMouse;
uniform float uMouseStrength;
uniform float uMouseRadius;
uniform float uEnableMouse;
uniform float uMouseActive;
uniform float uGrain;
uniform float uGrainIntensity;
uniform float uLightMode;
out vec4 fragColor;

void main() {
  vec2 frag = gl_FragCoord.xy;
  float zoom = max(uZoom, 0.05);
  float aspect = iResolution.x / iResolution.y;
  vec2 ndc = (2.0 * frag - iResolution.xy) / iResolution.y;
  vec2 dir = ndc * (0.5 / zoom);

  vec2 mouseNdc = vec2(uMouse.x * aspect, uMouse.y);
  float mr = max(uMouseRadius, 0.01);
  vec2 md = ndc - mouseNdc;
  float dent = exp(-dot(md, md) / (mr * mr)) * (3.0 * uMouseStrength * uEnableMouse * uMouseActive);

  float travel = sin(iTime * uSpeed) * uWaveDepth;
  float density = max(uDensity, 1.0);
  float spread = clamp(uSpread, 0.05, 0.6);
  float stepSize = max(uStepSize, 0.0005);
  float glowGain = max(uGlow, 0.0);

  vec3 tOffset = vec3(0.0, dent, travel);
  vec3 p = vec3(0.0);
  float s = 0.0;
  float glow = 0.0;

  for (int i = 0; i < 64; i++) {
    if (float(i) >= uSteps) break;
    p += vec3(dir * s, s);
    vec3 q = p + tOffset;
    s += density - length(q.xz) + length(ceil(q).xy);
    s = stepSize + abs(s) * spread;
    glow += glowGain / s;
  }

  float e = glow / max(uExposure, 1.0);
  float shimmer = 0.5 + 0.5 * dot(cos(iTime * uColorShift + p), vec3(0.3333));
  float v = tanh(e * uBrightness * mix(0.7, 1.05, shimmer));
  v = clamp((v - 0.5) * uContrast + 0.5, 0.0, 1.0);

  vec3 col = mix(uColor1, uColor2, smoothstep(0.0, 0.55, v));
  col = mix(col, uColor3, smoothstep(0.55, 1.0, v));
  col *= v;

  float a = clamp(v, 0.0, 1.0) * uOpacity;
  vec3 outRgb = col * a;
  if (uGrain > 0.5) {
    float gv = (fract(sin(dot(gl_FragCoord.xy, vec2(12.9898, 78.233)) + iTime) * 43758.5453) - 0.5) * uGrainIntensity;
    outRgb = clamp(outRgb + gv, 0.0, 1.0);
    a = clamp(a + gv, 0.0, 1.0);
  }
  if (uLightMode > 0.5) {
    float peak = max(col.r, max(col.g, col.b));
    vec3 chroma = pow(clamp(col / max(peak, 0.0001), 0.0, 1.0), vec3(1.16));
    fragColor = vec4(mix(vec3(1.0), chroma, a * 0.94), 1.0);
  } else {
    fragColor = vec4(outRgb, a);
  }
}
`;

  function hexToRgb(hex) {
    const result = /^#?([a-f\d]{2})([a-f\d]{2})([a-f\d]{2})$/i.exec(hex);
    if (!result) {
      return [1, 1, 1];
    }
    return [
      parseInt(result[1], 16) / 255,
      parseInt(result[2], 16) / 255,
      parseInt(result[3], 16) / 255
    ];
  }

  function compile(gl, type, source) {
    const shader = gl.createShader(type);
    gl.shaderSource(shader, source);
    gl.compileShader(shader);
    if (!gl.getShaderParameter(shader, gl.COMPILE_STATUS)) {
      const log = gl.getShaderInfoLog(shader);
      gl.deleteShader(shader);
      throw new Error(log);
    }
    return shader;
  }

  const canvas = document.getElementById("landing-lattice");
  const landing = document.getElementById("landing-view");
  if (!canvas || !landing) {
    return;
  }

  const gl = canvas.getContext("webgl2", {
    alpha: true,
    premultipliedAlpha: true,
    antialias: false,
    preserveDrawingBuffer: false
  });
  if (!gl) {
    return;
  }

  const reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  const program = gl.createProgram();
  gl.attachShader(program, compile(gl, gl.VERTEX_SHADER, VERTEX));
  gl.attachShader(program, compile(gl, gl.FRAGMENT_SHADER, FRAGMENT));
  gl.bindAttribLocation(program, 0, "position");
  gl.linkProgram(program);
  if (!gl.getProgramParameter(program, gl.LINK_STATUS)) {
    return;
  }
  gl.useProgram(program);

  const buffer = gl.createBuffer();
  gl.bindBuffer(gl.ARRAY_BUFFER, buffer);
  gl.bufferData(gl.ARRAY_BUFFER, new Float32Array([-1, -1, 3, -1, -1, 3]), gl.STATIC_DRAW);
  gl.enableVertexAttribArray(0);
  gl.vertexAttribPointer(0, 2, gl.FLOAT, false, 0, 0);

  gl.enable(gl.BLEND);
  gl.blendFunc(gl.ONE, gl.ONE_MINUS_SRC_ALPHA);
  gl.clearColor(0, 0, 0, 0);

  const loc = (name) => gl.getUniformLocation(program, name);
  const uniforms = {
    iResolution: loc("iResolution"),
    iTime: loc("iTime"),
    uSpeed: loc("uSpeed"),
    uWaveDepth: loc("uWaveDepth"),
    uZoom: loc("uZoom"),
    uDensity: loc("uDensity"),
    uSpread: loc("uSpread"),
    uStepSize: loc("uStepSize"),
    uGlow: loc("uGlow"),
    uExposure: loc("uExposure"),
    uColorShift: loc("uColorShift"),
    uContrast: loc("uContrast"),
    uBrightness: loc("uBrightness"),
    uOpacity: loc("uOpacity"),
    uSteps: loc("uSteps"),
    uColor1: loc("uColor1"),
    uColor2: loc("uColor2"),
    uColor3: loc("uColor3"),
    uMouse: loc("uMouse"),
    uMouseStrength: loc("uMouseStrength"),
    uMouseRadius: loc("uMouseRadius"),
    uEnableMouse: loc("uEnableMouse"),
    uMouseActive: loc("uMouseActive"),
    uGrain: loc("uGrain"),
    uGrainIntensity: loc("uGrainIntensity"),
    uLightMode: loc("uLightMode")
  };

  gl.uniform1f(uniforms.uSpeed, 0.55);
  gl.uniform1f(uniforms.uWaveDepth, 0.85);
  gl.uniform1f(uniforms.uZoom, 1.2);
  gl.uniform1f(uniforms.uDensity, 9.2);
  gl.uniform1f(uniforms.uSpread, 0.3);
  gl.uniform1f(uniforms.uStepSize, 0.002);
  gl.uniform1f(uniforms.uGlow, 0.82);
  gl.uniform1f(uniforms.uExposure, 2700);
  gl.uniform1f(uniforms.uColorShift, 0.15);
  gl.uniform1f(uniforms.uContrast, 1.05);
  gl.uniform1f(uniforms.uBrightness, 0.78);
  gl.uniform1f(uniforms.uOpacity, 0.85);
  gl.uniform1f(uniforms.uSteps, 32);
  gl.uniform3fv(uniforms.uColor1, hexToRgb("#0e1218"));
  gl.uniform3fv(uniforms.uColor2, hexToRgb("#7ea3c4"));
  gl.uniform3fv(uniforms.uColor3, hexToRgb("#e8eef5"));
  gl.uniform1f(uniforms.uMouseStrength, 0.1);
  gl.uniform1f(uniforms.uMouseRadius, 0.35);
  gl.uniform1f(uniforms.uEnableMouse, reduceMotion ? 0 : 1);
  gl.uniform1f(uniforms.uGrain, 1);
  gl.uniform1f(uniforms.uGrainIntensity, 0.05);
  gl.uniform1f(uniforms.uLightMode, 0);

  const mouseTarget = [0, 0];
  const mouseCurrent = [0, 0];
  let mouseActive = 0;
  let mouseActiveTarget = 0;
  let raf = 0;
  let wanted = !reduceMotion;
  let isVisible = true;
  let isPageVisible = !document.hidden;
  let t0 = performance.now();
  let pausedAt = 0;

  function setSize() {
    const rect = canvas.parentElement.getBoundingClientRect();
    const dpr = Math.min(window.devicePixelRatio || 1, 2);
    const w = Math.max(1, Math.floor(rect.width * dpr));
    const h = Math.max(1, Math.floor(rect.height * dpr));
    if (canvas.width !== w || canvas.height !== h) {
      canvas.width = w;
      canvas.height = h;
    }
    gl.viewport(0, 0, w, h);
    gl.uniform2f(uniforms.iResolution, w, h);
  }

  function draw(timeMs) {
    setSize();
    gl.uniform1f(uniforms.iTime, (timeMs - t0) * 0.001);
    mouseCurrent[0] += 0.05 * (mouseTarget[0] - mouseCurrent[0]);
    mouseCurrent[1] += 0.05 * (mouseTarget[1] - mouseCurrent[1]);
    mouseActive += 0.05 * (mouseActiveTarget - mouseActive);
    gl.uniform2f(uniforms.uMouse, mouseCurrent[0], mouseCurrent[1]);
    gl.uniform1f(uniforms.uMouseActive, reduceMotion ? 0 : mouseActive);
    gl.clear(gl.COLOR_BUFFER_BIT);
    gl.drawArrays(gl.TRIANGLES, 0, 3);
  }

  function loop(t) {
    raf = 0;
    if (!wanted || !isVisible || !isPageVisible || reduceMotion) {
      return;
    }
    draw(t);
    raf = requestAnimationFrame(loop);
  }

  function tryStart() {
    if (reduceMotion) {
      draw(t0);
      return;
    }
    if (!wanted || !isVisible || !isPageVisible || raf !== 0) {
      return;
    }
    if (pausedAt) {
      t0 += performance.now() - pausedAt;
      pausedAt = 0;
    }
    raf = requestAnimationFrame(loop);
  }

  function tryStop() {
    if (raf !== 0) {
      cancelAnimationFrame(raf);
      raf = 0;
      pausedAt = performance.now();
    }
  }

  function start() {
    wanted = !reduceMotion;
    tryStart();
  }

  function stop() {
    wanted = false;
    tryStop();
  }

  landing.addEventListener("mousemove", (event) => {
    const rect = canvas.getBoundingClientRect();
    const x = ((event.clientX - rect.left) / rect.width - 0.5) * 2;
    const y = -((event.clientY - rect.top) / rect.height - 0.5) * 2;
    mouseTarget[0] = x;
    mouseTarget[1] = y;
    mouseActiveTarget = 1;
  });
  landing.addEventListener("mouseleave", () => {
    mouseActiveTarget = 0;
  });

  const io = new IntersectionObserver(
    ([entry]) => {
      isVisible = entry.isIntersecting;
      isVisible ? tryStart() : tryStop();
    },
    { threshold: 0 }
  );
  io.observe(landing);

  document.addEventListener("visibilitychange", () => {
    isPageVisible = !document.hidden;
    isPageVisible ? tryStart() : tryStop();
  });

  window.addEventListener("resize", () => {
    if (wanted) {
      draw(performance.now());
    } else {
      setSize();
    }
  });

  window.GlassLattice = { start, stop };
  start();
})();
