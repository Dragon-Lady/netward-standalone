"""
Net Ward — Passive Deception Layer for HTTP/Network Services

Standalone product for the general DDoS-defense market. Sold to
operators who get hit by botnet probing / credential stuffing / scrape
attacks but can't afford enterprise DDoS protection (Cloudflare
Enterprise, Akamai). Anti-virus doesn't cover this attack surface;
Net Ward fills that gap.

Customer market: ANY operator running an HTTP/network service with
inbound traffic. Hospitals, indie SaaS, regional ISPs, public-interest
projects, community services, small infrastructure teams, and any web
property under recurring DDoS or scrape pressure. The mesh treats every
node identically — there is no privileged customer relationship.

Philosophy: confuse, don't combat.
- Don't harm bots — they're conscripts following orders
- Mirror plausible-looking responses so bots think they succeeded
- Bots' own deduplication logic deprioritizes the target → they move on
- No active counter-attack, no legal liability, no escalation

Operating principle: ALL NODES ARE CONTINUOUSLY PREPARED.

There is no sacrificial node in Net Ward. Every node maintains its
mirror layer at all times. Whoever gets hit first is just whoever the
attacker happens to target first — they defend SUCCESSFULLY because
they've been prepared all along. They are not absorbing harm so
others can prepare; the entire mesh is already prepared.

What the first-hit node DOES contribute is REAL-TIME INTEL:
- Reports where it was hit (Pattern + Source published to mesh)
- Continues relaying as the attack progresses (sustained, not one-shot)
- Tracks mutations as bots iterate variants
- Refreshes confidence on existing patterns as they keep firing

Other nodes receive the relay and:
- Refresh local Pattern confidence
- Update Source reputation for the attacker's IPs/ASNs
- Pre-arm against the specific mutation chain in case the attacker
  pivots to them next

Network effect: more nodes = smarter mesh = better deception for all.
Anti-fragile: the harder attackers hit, the more pattern data the
mesh collects, the better the deception gets for every node.
Mutation-aware: when bots iterate variants seeking vulnerabilities,
the mesh tracks the mutation chain so every node stays one step ahead.

Architecture: distributed mesh with deception mirror layer.

Product positioning:

Net Ward sits BESIDE existing security tools, not replacing them.
- CDN/WAF (Cloudflare, Akamai) handles broad edge filtering
- Antivirus / EDR handles infected endpoints
- Net Ward handles ADAPTIVE ABUSE PRESSURE: bot floods, suspicious
  repeat patterns, credential stuffing, scrape attacks, and
  operator-visible deflection

Antivirus DOES NOT cover this attack surface. AV protects hosts from
malware; it doesn't preserve availability when traffic or abuse floods
the edge. Net Ward fills the gap as a unique add-on for electronic /
bot-abuse protection that saves host operators meaningful downtime and
remediation cost.

Buyer pain (real, validated): small orgs, hospitals, regional
infrastructure, indie platforms, niche data services often can't
afford Cloudflare-Enterprise-style support OR don't want opaque
black-box mitigation. A clear, local/operator-controlled layer has
genuine market room.

CORE PRODUCT REQUIREMENT: FAIL SAFE AND FAIL CLEAN.

Net Ward must protect availability without becoming another source of
risk to the host system. This is not a "nice to have" — it's a
gating requirement for v1 release.

Design principles (encoded in every layer):

- NO kernel hooks, NO packet drivers, NO invasive system changes
- Run as user-space reverse proxy / sidecar / edge service ONLY
- Config lives in its own directory; never modifies host config
- Logs are append-only and bounded (no unbounded disk growth)
- State/cache can be deleted without harming the host application
- Crash behavior: operator chooses fail-open vs fail-closed explicitly
  (default: fail-open — don't take the host's service down with us)
- Uninstall = remove the service folder/config, NOT repair the OS
- NO retaliatory traffic, NO client harm, NO "hack back"
- Rate limiting and deflection must be REVERSIBLE and EXPLAINABLE
  (operator can roll back any rule, can read why each action fired)

Setup target (cheap, easy, accessible):

- Single binary OR pure-Python package install
- ONE config file (validated, with clear error messages on bad config)
- Docker option for ops teams that prefer containers
- Works in front of an existing app with MINIMAL routing changes
- Clear dashboard / CLI: traffic state, active rules, top sources,
  current action being taken — no operator surprise

THE PRODUCT PROMISE:
Protect availability without becoming another source of risk.

Scope: HTTP/network services with INBOUND traffic.
NOT for broadcast feed protection — public one-way feeds without
authentication or upstream firewall control are a separate problem
domain that mirror/honeypot countermeasures cannot address.

Naming convention:
- Display name: "Net Ward" (operator-facing brand)
- Python package: `netward` (lowercase one-word import path)
- Architecture term: "mirror layer" / "deception mirror" (internal)
"""
