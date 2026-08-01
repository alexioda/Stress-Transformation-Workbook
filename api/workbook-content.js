// api/workbook-content.js
// Vercel serverless function — returns the workbook's actual chapter content.
// Previously this HTML lived directly in index.html's <main>, which meant
// the lock screen was cosmetic: viewing page source (or disabling JS)
// exposed the entire paid workbook regardless of the cipher. Now the content
// only exists in this file and is served after verifying the signed session
// token issued by api/authenticate-workbook.js.
//
// SETUP: set SESSION_SECRET in this project's Vercel environment variables
// (same value doesn't need to match any other app's secret — each Vercel
// project is isolated). Until it's set, this endpoint returns a 500 and the
// workbook content will not load, even with a correct cipher — DEVMODE
// continues to work in non-production deployments regardless, so local
// testing isn't blocked.
//
// Sessions are stored client-side in localStorage (not sessionStorage) so a
// buyer stays logged in on a given device across tabs/restarts for up to a
// year, whether they got in via the manual cipher or a Lemon Squeezy license
// key (see api/authenticate-workbook.js) — a new device still needs one of
// those entered once.

const crypto = require('crypto');

function isValidSessionToken(token) {
  // Non-production dev fallback — mirrors api/authenticate-workbook.js.
  if (token === 'dev' && process.env.VERCEL_ENV !== 'production') return true;

  const secret = process.env.SESSION_SECRET;
  if (!secret) return null; // "not configured" — distinct from "invalid"
  if (!token || typeof token !== 'string') return false;

  const parts = token.split('.');
  if (parts.length !== 2) return false;
  const [issuedAt, signature] = parts;
  if (!/^\d+$/.test(issuedAt)) return false;

  const expected = crypto.createHmac('sha256', secret).update(issuedAt).digest('hex');
  const sigBuf = Buffer.from(signature, 'hex');
  const expBuf = Buffer.from(expected, 'hex');
  if (sigBuf.length !== expBuf.length) return false;
  if (!crypto.timingSafeEqual(sigBuf, expBuf)) return false;

  const MAX_AGE_MS = 365 * 24 * 60 * 60 * 1000; // sessions are remembered for a year
  const age = Date.now() - Number(issuedAt);
  return age >= 0 && age <= MAX_AGE_MS;
}

module.exports = function handler(req, res) {
  if (req.method !== 'GET') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const token = req.headers['x-workbook-token'];
  const valid = isValidSessionToken(token);

  if (valid === null) {
    return res.status(500).json({ error: 'Server configuration error: SESSION_SECRET is not set.' });
  }
  if (!valid) {
    return res.status(401).json({ error: 'Invalid or expired session. Please re-authenticate.' });
  }

  return res.status(200).json({ html: WORKBOOK_HTML });
};

const WORKBOOK_HTML = `

  <!-- INTRO -->
  <section id="intro" style="padding-bottom:80px; border-bottom:1px solid var(--border);">
    <div style="text-transform:uppercase; letter-spacing:3px; font-size:0.85rem; color:var(--forest); margin-bottom:20px; font-weight:700;">
      The Architect's Edition
    </div>
    <h1>Stress Transformation<br>Workbook</h1>
    <p style="font-size:1.5rem; font-family:var(--font-serif); font-style:italic; color:var(--text-muted); margin-top:-8px;">
      "Architecture for the Modern Soul"
    </p>

    <div style="margin-top:56px;">
      <p><strong>Preface: The Paradigm Shift</strong></p>
      <p>We are in a crisis of "Stress Management." The world teaches you to treat stress like a toxic waste product — something to be reduced, numbed, or avoided. This is the path of <strong>Fragility</strong>.</p>
      <p>We take the path of <strong>Antifragility</strong>. We do not ask for lighter burdens; we build stronger backs. We fuse ancient wisdom with modern neuroscience to prove a single, radical truth:</p>
      <blockquote style="border-color:var(--charcoal); background:white;">
        Stress is not the enemy. Stress is energy. And energy can be shaped.
      </blockquote>
      <p>This workbook weaves the pillars of conscious growth — <strong>Biology, Stoicism, Taoism, and Depth Psychology</strong> — into a practical framework for self-fulfillment. It is not a document to be read. It is a tool to be used.</p>
      <p style="font-size:0.88rem; color:var(--gold); font-weight:600;">
        * All your inputs are automatically saved to your device.
      </p>
    </div>
  </section>

  <!-- CHAPTER 1 -->
  <section id="science">
    <h2>1. The Physiology of Perception</h2>
    <p>Before we touch philosophy, we must ground ourselves in biology. You have been told that stress kills. This is the half-truth.</p>

    <div class="concept-box">
      <div class="concept-header"><span class="tag">Research</span> The 2012 Keller Study</div>
      <p>Researchers tracked 30,000 adults for 8 years. <strong>Result:</strong> High stress increased the risk of death by 43% — but <em>only</em> for those who believed it was harmful. Those with high stress who viewed it as a challenge had the <em>lowest</em> death rate of anyone in the study.</p>
    </div>

    <p>This is the <strong>Belief Effect.</strong> When you view stress as a threat, your amygdala hijacks your brain. When you view it as a challenge, your prefrontal cortex engages. Same stimulus. Different architecture.</p>

    <h3>The Physiological Sigh</h3>
    <p>We cannot control the mind with the mind — we must use the body. Dr. Andrew Huberman's research identifies the <strong>Physiological Sigh</strong> as the fastest mechanical reset for the nervous system: a double inhale through the nose followed by a long, slow exhale through the mouth.</p>
    <p style="font-size:0.9rem; color:var(--text-muted); font-style:italic;">
      Follow the animation below for 60 seconds. Let the body lead.
    </p>

    <div class="visual-container">
      <div class="breath-wrapper">
        <div class="breath-outer">
          <div class="breath-ring"></div>
          <div class="breath-circle">
            <div class="breath-label" id="breath-label">Inhale</div>
          </div>
        </div>
        <div class="breath-phase" id="breath-phase">First inhale — nose</div>
        <p class="breath-instruction">Double inhale (nose) → Long exhale (mouth) · 8 second cycle</p>
      </div>
    </div>
  </section>

  <!-- CHAPTER 2 -->
  <section id="stoic">
    <h2>2. The Stoic Fortress</h2>
    <blockquote>
      "It is not events that disturb people, but their judgments concerning them."
      <cite>— Epictetus</cite>
    </blockquote>

    <p>Stress is usually the friction caused by trying to control the uncontrollable — the market, other people, outcomes. This is an energy leak. The Stoics called this confusing the <em>preferred indifferent</em> with the <em>good</em>.</p>

    <div class="concept-box">
      <div class="concept-header"><span class="tag">Allegory</span> The Archer</div>
      <p>A Stoic Archer puts everything into his stance, his aim, his release. Once the arrow leaves the bow, he does not panic. A gust of wind may move it. He knows his worth lives in the <em>aiming</em> — the internal — not the <em>hitting</em> — the external.</p>
    </div>

    <div class="visual-container">
      <svg width="400" height="280" viewBox="0 0 400 280">
        <circle cx="200" cy="140" r="120" fill="none" stroke="#ccc" stroke-width="1.5" stroke-dasharray="6,4"/>
        <text x="200" y="38" text-anchor="middle" fill="#aaa" font-size="11" font-family="sans-serif" font-weight="600">THE EXTERNAL</text>
        <text x="200" y="52" text-anchor="middle" fill="#bbb" font-size="9" font-family="sans-serif" font-style="italic">(Outcomes · Reputation · Results)</text>
        <circle cx="200" cy="140" r="58" fill="#2C5F2D" opacity="0.08"/>
        <circle cx="200" cy="140" r="58" fill="none" stroke="#2C5F2D" stroke-width="2.5"/>
        <text x="200" y="136" text-anchor="middle" fill="#2C5F2D" font-weight="700" font-size="12" font-family="sans-serif">THE FORTRESS</text>
        <text x="200" y="154" text-anchor="middle" fill="#2C5F2D" font-size="10" font-family="sans-serif">(Mind · Choice · Action)</text>
      </svg>
    </div>

    <div class="reflection-card">
      <span class="save-indicator">Saved ✓</span>
      <div class="reflection-title">⚡ Stoic Audit</div>
      <p>List three things currently generating friction. For each: is it inside or outside the fortress?</p>
      <textarea id="reflection-1" placeholder="1. The deadline (Outside) — my preparation (Inside)..."></textarea>
    </div>
  </section>

  <!-- CHAPTER 3 -->
  <section id="tao">
    <h2>3. The Tao of Flow</h2>
    <p>While Stoicism gives us strength — the rock — <strong>Taoism</strong> gives us flexibility — the water. A rigid tree breaks in the storm. Bamboo bends and survives. Both are necessary.</p>

    <div class="concept-box">
      <div class="concept-header"><span class="tag">Allegory</span> The Empty Boat</div>
      <p>If a boat crashes into yours, you yell at the captain. But if the boat is empty, your anger vanishes immediately. The event is identical. The <em>intent</em> is what hurt you. Recognize that most of what the universe sends is an empty boat. It isn't personal.</p>
    </div>

    <h3>Resistance vs. Acceptance</h3>
    <p>Friction is the resistance of pushing against reality. <em>"This shouldn't be happening"</em> is the most expensive sentence in the human language. The replacement: <strong>"What does this moment require of me?"</strong></p>
  </section>

  <!-- CHAPTER 4 -->
  <section id="energy">
    <h2>4. Energy Leadership</h2>
    <p>Every response to friction is an energy choice. Energy Leadership® — developed by Bruce D Schneider and the Institute for Professional Excellence in Coaching (iPEC) — distinguishes seven levels of energetic response, ranging from pure drain to pure creation.</p>

    <div class="energy-grid">
      <div class="energy-card energy-catabolic">
        <h4>Catabolic Energy</h4>
        <p style="font-size:0.88rem; margin-bottom:12px;">Draining, contracting, resisting. Fueled by cortisol and adrenaline. Useful for short-term survival — corrosive for sustained leadership.</p>
        <ul>
          <li><strong>Level 1 — The Victim:</strong> "I lose. There's nothing I can do."</li>
          <li><strong>Level 2 — The Fighter:</strong> "You lose. I win by force."</li>
          <li><strong>Level 3 — The Rationalizer:</strong> "I'll tolerate this — for now."</li>
        </ul>
      </div>
      <div class="energy-card energy-anabolic">
        <h4>Anabolic Energy</h4>
        <p style="font-size:0.88rem; margin-bottom:12px;">Fueling, expanding, creating. Sustained by oxytocin and intrinsic motivation. Regenerative and scalable.</p>
        <ul>
          <li><strong>Level 4 — The Caregiver:</strong> "I serve. Others first."</li>
          <li><strong>Level 5 — The Opportunist:</strong> "Win/Win. Every challenge holds a gift."</li>
          <li><strong>Level 6 — The Synergist:</strong> "We are one system."</li>
          <li><strong>Level 7 — The Creator:</strong> "Pure presence. Absolute creation."</li>
        </ul>
      </div>
    </div>

    <p class="eli-attribution">
      Energy Leadership® is a registered trademark of iPEC (Institute for Professional Excellence in Coaching).<br>
      The 7-level framework is proprietary to iPEC and used here under practitioner certification.
    </p>

    <div class="reflection-card">
      <span class="save-indicator">Saved ✓</span>
      <div class="reflection-title">⚡ Energy Diagnostic</div>
      <p>Regarding your current primary stressor — which level are you operating from? What would it look like to move one level higher?</p>
      <textarea id="reflection-2" placeholder="Right now I am operating at Level ___ because... Moving to Level ___ would mean..."></textarea>
    </div>
  </section>

  <!-- CHAPTER 5 -->
  <section id="shadow">
    <h2>5. Shadow Work: The Hidden Driver</h2>
    <p>Sometimes we sustain stress because a part of us <em>needs</em> it. This is the Shadow. Jung taught that until we make the unconscious conscious, it will direct our life and we will call it fate.</p>

    <div class="concept-box">
      <div class="concept-header"><span class="tag">Psychology</span> The Hidden Benefit</div>
      <p><strong>Ask:</strong> "What do I get to avoid by staying this stressed?"</p>
      <ul style="padding-left:20px; margin-top:10px;">
        <li style="margin-bottom:6px;">Does stress make you feel important? <em>(The Martyr)</em></li>
        <li style="margin-bottom:6px;">Does stress protect you from intimacy? <em>(The Shield)</em></li>
        <li>Does stress validate your effort? <em>(The Hustler)</em></li>
      </ul>
    </div>

    <div class="reflection-card">
      <span class="save-indicator">Saved ✓</span>
      <div class="reflection-title">⚡ Shadow Inquiry</div>
      <p>If this friction were a person standing guard, what is it protecting you from?</p>
      <textarea id="reflection-3" placeholder="Perhaps it is protecting me from..."></textarea>
    </div>
  </section>

  <!-- CHAPTER 6 -->
  <section id="mirror">
    <h2>6. The Metaphysical Mirror</h2>
    <blockquote>
      "Whatever the present moment contains, accept it as if you had chosen it."
      <cite>— Eckhart Tolle</cite>
    </blockquote>

    <p>Beyond biology and psychology lies the ontological: <strong>reality as reflection.</strong> This perspective holds that the external world does not happen <em>to</em> you but mirrors your inner state. The friction you feel is not caused by the event — it is caused by your resistance to the event.</p>

    <div class="concept-box">
      <div class="concept-header"><span class="tag">Metaphysics</span> The Mirror Principle</div>
      <p>If you look in a mirror and see a frown, you cannot fix it by scrubbing the glass. You must change your expression.</p>
      <p>If you encounter friction, chaos, or conflict — it often signals inner turbulence. The situation is neutral. The trigger is yours. It points precisely to where you are not yet free.</p>
    </div>

    <h3>The Invitation to Evolve</h3>
    <p>Every trigger is a teacher. Impatience in traffic teaches patience. Anxiety about a deadline teaches self-worth independent of achievement. Friction is the universe pointing at the exact part of your architecture that is ready to be rebuilt.</p>

    <div class="reflection-card">
      <span class="save-indicator">Saved ✓</span>
      <div class="reflection-title">⚡ Mirror Inquiry</div>
      <p>If this situation is a mirror — what is it reflecting about your inner world right now?</p>
      <textarea id="reflection-mirror" placeholder="It is showing me that I still believe..."></textarea>
    </div>
  </section>

  <!-- CHAPTER 7 -->
  <section id="existential">
    <h2>7. The Existential Anchor</h2>
    <blockquote>
      "He who has a why to live can bear almost any how."
      <cite>— Friedrich Nietzsche</cite>
    </blockquote>

    <p>Viktor Frankl discovered that meaning was the primary drive of human existence — not pleasure, not power. Friction without meaning is suffering. Friction <em>with</em> meaning is growth. The architecture of resilience is built on purpose, not comfort.</p>

    <div class="concept-box">
      <div class="concept-header"><span class="tag">Allegory</span> Sisyphus</div>
      <p>Camus described Sisyphus condemned to roll a boulder up a hill for eternity. It seems like torture. But Camus concludes: <em>"One must imagine Sisyphus happy."</em> Why? Because the boulder belongs to him. Your friction is your boulder. You cannot drop it — but you can choose to own the pushing.</p>
    </div>
  </section>

  <!-- CHAPTER 8 -->
  <section id="cycle">
    <h2>8. The Growth Cycle</h2>
    <p>Consider the lobster — a soft animal living inside a rigid shell. As it grows, the shell becomes tight and painful. The lobster does not medicate the discomfort. It recognizes friction as the signal to shed what no longer fits.</p>
    <p>Stress is not a malfunction. It is the pressure of your next form arriving.</p>

    <div class="visual-container">
      <svg width="500" height="340" viewBox="0 0 500 340">
        <defs>
          <marker id="arrow-gold" markerWidth="10" markerHeight="10" refX="0" refY="3" orient="auto" markerUnits="strokeWidth">
            <path d="M0,0 L0,6 L9,3 z" fill="#b2945e"/>
          </marker>
          <marker id="arrow-red" markerWidth="10" markerHeight="10" refX="0" refY="3" orient="auto" markerUnits="strokeWidth">
            <path d="M0,0 L0,6 L9,3 z" fill="#E63946"/>
          </marker>
          <marker id="arrow-green" markerWidth="10" markerHeight="10" refX="0" refY="3" orient="auto" markerUnits="strokeWidth">
            <path d="M0,0 L0,6 L9,3 z" fill="#2C5F2D"/>
          </marker>
        </defs>
        <text x="250" y="36" text-anchor="middle" font-weight="700" fill="#333" font-family="sans-serif" font-size="13">COMFORT</text>
        <text x="250" y="52" text-anchor="middle" font-size="10" fill="#999" font-style="italic" font-family="sans-serif">Stasis</text>
        <path d="M285 60 Q 450 95 445 170" fill="none" stroke="#b2945e" stroke-width="2" marker-end="url(#arrow-gold)" stroke-dasharray="5,4"/>
        <text x="448" y="196" text-anchor="middle" font-weight="700" fill="#E63946" font-family="sans-serif" font-size="13">PRESSURE</text>
        <text x="448" y="212" text-anchor="middle" font-size="10" fill="#E63946" font-style="italic" font-family="sans-serif">Friction</text>
        <path d="M418 228 Q 250 315 82 228" fill="none" stroke="#E63946" stroke-width="2.5" marker-end="url(#arrow-red)"/>
        <text x="250" y="308" text-anchor="middle" font-weight="700" fill="#b8860b" font-family="sans-serif" font-size="13">VULNERABILITY</text>
        <text x="250" y="324" text-anchor="middle" font-size="10" fill="#b8860b" font-style="italic" font-family="sans-serif">Shedding</text>
        <path d="M52 175 Q 52 95 215 58" fill="none" stroke="#2C5F2D" stroke-width="2" marker-end="url(#arrow-green)"/>
        <text x="52" y="196" text-anchor="middle" font-weight="700" fill="#2C5F2D" font-family="sans-serif" font-size="13">EXPANSION</text>
        <text x="52" y="212" text-anchor="middle" font-size="10" fill="#2C5F2D" font-style="italic" font-family="sans-serif">New form</text>
        <text x="250" y="178" text-anchor="middle" font-size="52">🦞</text>
      </svg>
    </div>
  </section>

  <!-- CHAPTER 9 -->
  <section id="balance">
    <div class="dark-section">
      <h2>9. The Miraculous Balance</h2>
      <p style="font-size:1.15rem;">We spend our lives chasing an ideal state. But the Alchemist knows: <strong style="color:var(--gold-light)">Perfect is Now.</strong></p>

      <blockquote>
        "This moment is a miraculous balance of what was and what will be. It is our unquiet mind that creates the sense of lack, thirst, and hunger — not the moment itself."
      </blockquote>

      <p>There is no imperfection in this moment. The imbalance you feel is the ego creating a gap between <em>what is</em> and <em>what it wants</em>. Close the ledger. The gap is manufactured.</p>

      <div class="reflection-card">
        <span class="save-indicator" style="color:var(--gold)">Saved ✓</span>
        <div class="reflection-title">⚡ The Zero-Point Check</div>
        <p style="color:#a8a29e;">Look at your stressor again. If this moment is the only reality — what is actually missing right now, in this exact second?</p>
        <textarea id="reflection-balance" placeholder="My mind says I lack [X], but in this exact second, I have..."></textarea>
      </div>
    </div>
  </section>

  <!-- CHAPTER 10 -->
  <section id="integration">
    <h2>10. The Integration Protocol</h2>
    <p>Transformation is not intellectual — it is somatic and behavioral. You cannot think your way into a new way of acting. You must act your way into a new way of thinking.</p>

    <div class="protocol-box">
      <h3>The Field Protocol</h3>
      <div class="protocol-step">
        <div class="protocol-num">1</div>
        <div class="protocol-text"><strong>Somatic Reset (Biology):</strong> When friction hits — breathe first. Two short inhales through the nose, one long exhale through the mouth.</div>
      </div>
      <div class="protocol-step">
        <div class="protocol-num">2</div>
        <div class="protocol-text"><strong>The Stoic Stop (Philosophy):</strong> "Is this outcome entirely within my control?" If no — redirect energy inward.</div>
      </div>
      <div class="protocol-step">
        <div class="protocol-num">3</div>
        <div class="protocol-text"><strong>The Mirror Check (Metaphysics):</strong> "What is this friction reflecting about my inner state?"</div>
      </div>
      <div class="protocol-step">
        <div class="protocol-num">4</div>
        <div class="protocol-text"><strong>The Zero-Point (Presence):</strong> "Close the ledger. Perfect is now."</div>
      </div>
      <div class="protocol-step">
        <div class="protocol-num">5</div>
        <div class="protocol-text"><strong>The Meaning Anchor (Existentialism):</strong> "Who am I becoming by navigating this?"</div>
      </div>
    </div>

    <div class="reflection-card">
      <span class="save-indicator">Saved ✓</span>
      <div class="reflection-title">⚡ Final Commitment</div>
      <p>I commit to using my current friction not as a reason to retreat, but as fuel for...</p>
      <textarea id="reflection-4" placeholder="Write your commitment here..."></textarea>
    </div>

    <div style="text-align:center; margin-top:60px;">
      <button onclick="window.print()"
        style="background:var(--charcoal); color:white; border:none; padding:18px 48px;
               font-size:0.9rem; border-radius:50px; cursor:pointer; letter-spacing:2px;
               font-weight:700; text-transform:uppercase; font-family:var(--font-sans);
               box-shadow:0 4px 15px rgba(0,0,0,0.12); transition:all 0.3s;">
        Print / Save as PDF
      </button>
    </div>

    <div class="upsell-section">
      <h3 style="margin-top:0; font-family:var(--font-serif); color:var(--charcoal);">Continue the Work</h3>
      <p style="color:#666; font-style:italic; margin-bottom:0;">
        Transformation is a journey. The ecosystem continues here:
      </p>

      <div class="upsell-grid">
        <a href="https://app.liveadaptiv.com" class="upsell-btn btn-stone">
          <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect width="14" height="20" x="5" y="2" rx="2"/><path d="M12 18h.01"/></svg>
          LiveAdaptiv App
        </a>
        <a href="https://calendly.com/alexioda" class="upsell-btn btn-gold">
          <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="4" width="18" height="18" rx="2"/><line x1="16" y1="2" x2="16" y2="6"/><line x1="8" y1="2" x2="8" y2="6"/><line x1="3" y1="10" x2="21" y2="10"/></svg>
          Strategy Session
        </a>
      </div>

      <div class="upsell-socials">
        <a href="https://www.linkedin.com/in/alexioda" class="social-link">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-linecap="round" stroke-linejoin="round"><path d="M16 8a6 6 0 0 1 6 6v7h-4v-7a2 2 0 0 0-4 0v7h-4v-7a6 6 0 0 1 6-6z"/><rect x="2" y="9" width="4" height="12"/><circle cx="4" cy="4" r="2"/></svg>
          LinkedIn
        </a>
        <a href="https://www.facebook.com/share/1RmJbo4Gdt/" class="social-link">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-linecap="round" stroke-linejoin="round"><path d="M18 2h-3a5 5 0 0 0-5 5v3H7v4h3v8h4v-8h3l1-4h-4V7a1 1 0 0 1 1-1h3z"/></svg>
          Facebook
        </a>
        <a href="mailto:alex@liveadaptiv.com" class="social-link">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-linecap="round" stroke-linejoin="round"><path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"/><polyline points="22,6 12,13 2,6"/></svg>
          Email
        </a>
      </div>
    </div>
  </section>
`;
