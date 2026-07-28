# Cloud and orchestration networking (AWS, GCP, Kubernetes)

Deploying a custom protocol into a cloud or Kubernetes network breaks several assumptions
that hold on a LAN or on `localhost`. The connection now traverses NAT gateways, load
balancers with their own timeouts, overlay networks with reduced MTU, default-deny
firewalls, and ephemeral IPs. None of these are visible in unit tests, and each has a
specific failure mode for a long-lived, stateful, or latency-sensitive protocol.

This file maps those environment behaviors to what you must do in the protocol and its
deployment. It builds on `references/production-readiness.md` (graceful drain, health
signals, connection caps) and `references/protocol-design.md` (keepalive, MTU). The
`assets/k8s-deployment.yaml` manifest shows the Kubernetes pieces wired together for the
reference server.

## Table of contents

1. [What the cloud changes](#1-what-the-cloud-changes)
2. [Load balancers: L4 vs L7, and idle timeouts](#2-load-balancers)
3. [MTU and the overlay](#3-mtu-and-the-overlay)
4. [Seeing the real client IP (PROXY protocol)](#4-seeing-the-real-client-ip)
5. [AWS VPC](#5-aws-vpc)
6. [GCP networking](#6-gcp-networking)
7. [Kubernetes and the CNI](#7-kubernetes-and-the-cni)
8. [Deployment checklist](#8-deployment-checklist)

---

## 1. What the cloud changes

- **Default-deny firewalls.** Security groups (AWS), VPC firewall rules (GCP), and
  NetworkPolicies (k8s) start closed. Your port is unreachable until you explicitly allow
  it — for both ingress and, often, egress.
- **NAT everywhere.** Outbound-from-private goes through a NAT gateway; the peer's source
  IP you observe is frequently a load balancer or NAT address, not the real client (see §4).
- **Load balancers with their own lifetimes.** An LB sits between client and server and
  will silently drop connections it considers idle (see §2). This is the most common
  "works locally, dies in the cloud" cause for long-lived connections.
- **Overlay MTU < 1500.** Pod-to-pod traffic is often encapsulated (VXLAN/IP-in-IP),
  shrinking the usable MTU; large packets that worked on a LAN now black-hole (see §3).
- **Ephemeral, changing IPs.** Instances and pods come and go with new IPs; never hardcode
  peers — use DNS/service discovery, and make reconnection + retries first-class (with
  idempotency, pitfalls §8).

## 2. Load balancers

Choosing the LB type is the first decision for a custom protocol.

- **L4 (network/passthrough) LB** — forwards TCP/UDP without understanding your bytes:
  AWS **NLB**, GCP **passthrough Network Load Balancer**. This is what you want for a
  custom binary protocol: it doesn't try to parse or alter your stream. It preserves the
  protocol but typically terminates idle connections after a fixed window.
- **L7 (application) LB** — understands HTTP/gRPC and routes on it: AWS **ALB**, GCP
  **Application Load Balancer**. Use it only if your protocol *is* HTTP/gRPC/WebSocket; a
  raw binary protocol won't work through it.

**Idle timeouts are the trap.** Each LB closes connections with no traffic for some
period — AWS NLB defaults to **350 s**, ALB to **60 s**, GCP backend services have their
own. If your protocol leaves a connection idle longer than that, the LB sends a RST and
your "stable" connection dies — often seen as a `RST` in capture (packet-analysis §8).

The fix is an application-level **heartbeat shorter than the smallest idle timeout on the
path** (design §8): e.g. PING every 20–30 s keeps the connection live and detects a dead
peer. TCP keepalive can help but its defaults (hours) are far too long and not always
honored by middleboxes; an application heartbeat is reliable. Also make sure the LB's
timeout is **longer** than your heartbeat interval, with margin.

Health checks: an L4 LB health-checks by opening a TCP connection (or sending a probe);
your server must accept and (for an L7/HTTP check) answer it, or the LB marks the target
unhealthy and stops routing. Map this to a lightweight readiness path (production-readiness
§2).

## 3. MTU and the overlay

On a plain Ethernet LAN the MTU is 1500 bytes. In the cloud it varies, and inside
Kubernetes overlays it is usually **lower** (e.g. ~1450 for VXLAN, ~1400 for some
encrypted CNIs) because encapsulation headers eat into the 1500. Consequences:

- **TCP** mostly self-heals via MSS negotiation and Path MTU Discovery — *unless* ICMP
  "fragmentation needed" is blocked (common in cloud security groups), which black-holes
  large packets: the connection hangs on big messages while small ones work. If you see
  that, suspect MTU/ICMP, and consider **MSS clamping** on the path.
- **UDP** does not self-heal. Oversized datagrams fragment or get dropped. Keep datagrams
  small — the ≲1200-byte guidance in pitfalls §11.3 exists precisely for tunnelled/overlay
  paths. QUIC targets ~1200 for this reason.

When in doubt, measure: `ping -M do -s <size>` (don't-fragment) finds the path MTU, and a
capture shows fragmentation or ICMP errors.

## 4. Seeing the real client IP

Behind an L4 LB or NAT, the source IP your server sees is the **LB/NAT address**, not the
client's. This quietly breaks anything that depends on the client IP — including the
**per-IP connection cap** in `framed_protocol.py` (every connection appears to come from
one address, so the cap either does nothing or throttles everyone).

Options:
- **PROXY protocol** (v1/v2): the LB prepends a small header with the real client address
  before your bytes. AWS NLB and many proxies support it. Your server must parse and strip
  that header *before* the protocol handshake, then use the real IP for limits and logs.
- **Cloud-native preservation**: some LBs can preserve the client IP directly
  (e.g. NLB with client-IP preservation, or GCP passthrough LB which preserves it).
- For HTTP/L7, the `X-Forwarded-For` header carries it (but that's the HTTP case).

If you rely on per-IP limits or IP-based logging in production, decide which of these
you're using — don't assume `getpeername()` is the client.

## 5. AWS VPC

- **Subnets**: public (route to an Internet Gateway) vs private (egress via NAT Gateway).
  Put servers in private subnets; expose them through an LB in public subnets.
- **Security groups** (stateful, attached to ENIs): allow your port inbound from the LB's
  SG. Return traffic is automatic (stateful). Start from deny; add the minimum.
- **Network ACLs** (stateless, per-subnet): a coarser, stateless layer — remember to allow
  ephemeral return ports if you use them.
- **NLB vs ALB**: NLB (L4) for custom TCP/UDP; ALB (L7) only for HTTP-family. NLB idle
  timeout 350 s → heartbeat well under that.
- **MTU**: within a VPC up to 9001 (jumbo) is possible, but paths crossing certain
  boundaries fall back to 1500; don't assume jumbo end to end.
- **PrivateLink** exposes a service across VPCs/accounts without public exposure — good for
  an internal protocol.

## 6. GCP networking

- **VPC is global**; subnets are regional. Routing within a VPC is flat across regions.
- **Firewall rules** are stateful, allow/deny by tags/service accounts/CIDR; default-deny
  ingress. Allow your port from the LB or source range.
- **Cloud NAT** provides egress for instances without external IPs.
- **Load balancing**: the **passthrough Network LB** (L4) preserves the protocol and the
  client IP — the right choice for a raw protocol; the **Application LB** (L7) is for
  HTTP-family. Backend services define health checks and timeouts.
- **MTU**: VPC MTU is configurable (1460 default historically, up to 8896); keep the whole
  path consistent.
- **Private Service Connect** is the cross-VPC private-exposure analogue to PrivateLink.

## 7. Kubernetes and the CNI

The Kubernetes network model: every Pod gets its own IP and all Pods can reach each other
without NAT (a flat network), implemented by a **CNI plugin** (Calico, Cilium, flannel,
AWS VPC CNI, …). What this means for your protocol:

- **Services and kube-proxy.** A `ClusterIP` Service is a stable virtual IP load-balanced
  across Pods by kube-proxy (iptables or IPVS). For most client/server protocols this is
  fine. For **peer-to-peer or stateful** protocols where clients need to address individual
  Pods, use a **headless Service** (`clusterIP: None`) so DNS returns each Pod's IP, or a
  StatefulSet with stable Pod DNS names.
- **External exposure.** `LoadBalancer`-type Services provision a cloud L4 LB (with all the
  idle-timeout/PROXY-protocol caveats above); `NodePort` exposes a port on every node;
  Ingress is L7 (HTTP) and not for raw protocols.
- **Overlay MTU.** If your CNI uses VXLAN/IPIP, the Pod MTU is below 1500 (§3). Confirm it
  and keep UDP datagrams small.
- **NetworkPolicy.** By default all Pod traffic is allowed; a NetworkPolicy switches the
  selected Pods to default-deny, after which you must explicitly allow your port from the
  client Pods. Cilium/Calico add richer policy. Lock this down for a production service.
- **Probes map to your protocol's liveness/readiness** (production-readiness §2). A TCP
  `readinessProbe` on your port gates whether the Service routes to the Pod; a
  `livenessProbe` restarts a wedged Pod. Make readiness reflect "bound, warmed up, below
  the connection cap"; don't let a liveness probe kill a Pod that's merely busy.
- **Graceful shutdown is the big one.** On a rolling deploy or scale-down, Kubernetes sends
  `SIGTERM`, removes the Pod from Service endpoints, waits `terminationGracePeriodSeconds`,
  then `SIGKILL`s. To avoid dropping in-flight connections:
  - Handle SIGTERM by draining (stop accepting, finish in-flight) — exactly what
    `Server.shutdown()` + drain does.
  - Set `terminationGracePeriodSeconds` ≥ your `drain_timeout` so the drain can complete.
  - Optionally add a `preStop` hook sleep so the Pod is removed from endpoints *before* it
    stops accepting, closing the small race where the LB still sends new connections.
  - Flip readiness to "not ready" on SIGTERM so traffic stops being routed immediately.

`assets/k8s-deployment.yaml` shows a Deployment + Service + NetworkPolicy with these
probes, the grace period aligned to the drain timeout, and a preStop hook.

## 8. Deployment checklist

- [ ] Firewall/SG/NetworkPolicy explicitly allows the protocol port (ingress, and egress if
      default-deny). (§1, §5–7)
- [ ] L4 LB (NLB / passthrough) chosen for a raw protocol; L7 only if it's HTTP-family. (§2)
- [ ] Heartbeat interval is comfortably below the smallest LB/NAT idle timeout on the path;
      LB timeout has margin above it. (§2; design §8)
- [ ] Overlay/path MTU confirmed; UDP datagrams kept small; ICMP "frag needed" not blocked
      (or MSS clamped). (§3; pitfalls §11.3)
- [ ] Real client IP recovered (PROXY protocol or client-IP preservation) if per-IP limits
      or IP logging are used. (§4)
- [ ] Health/readiness/liveness probes wired to the protocol; readiness reflects capacity
      and flips on shutdown. (§7; production-readiness §2)
- [ ] SIGTERM triggers graceful drain; `terminationGracePeriodSeconds` ≥ drain timeout;
      preStop hook closes the endpoint-removal race. (§7; production-readiness §3)
- [ ] Reconnection + retries with backoff/jitter and idempotency, since instance/Pod IPs
      are ephemeral. (§1; pitfalls §8)
