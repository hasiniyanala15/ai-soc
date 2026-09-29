# I Gave My SOC Agent a Memory with Hindsight

A security alert is only useful if an analyst can understand what happened before it. I built a SOC agent that watches live network traffic, investigates suspicious activity with an LLM, and uses Hindsight to remember what it has seen.

That last part turned out to be more important than I expected.

## The problem with treating every security alert as new

A network monitor can tell me that something suspicious happened. It can identify packets, addresses, ports, protocols, and traffic patterns. An LLM can then help explain what that activity might mean.

But there is a fundamental limitation if every investigation starts from zero.

Suppose an IP address generates suspicious traffic today. The agent analyzes the alert and produces an explanation. Tomorrow, the same source appears again.

Without persistent memory, the second investigation is largely another isolated event.

The agent knows what is happening now, but it does not naturally know that something similar happened yesterday.

That is the problem I wanted to solve.

Instead of building an LLM wrapper around network alerts, I built the system around three connected pieces:

**Detect → Investigate → Remember**

Scapy handles the network side. The LLM handles investigation and explanation. Hindsight provides the persistent memory layer that connects investigations over time.

The result is a SOC workflow that can move from an individual alert toward a longer-running incident history.

## What the system actually does

The first part of the system is a live packet-monitoring pipeline built with Python and Scapy.

Rather than waiting for a log file to be uploaded, the agent can observe network traffic as it happens. From the packets it can work with information such as source and destination addresses, protocols, ports, timestamps, and traffic behavior.

The monitoring layer feeds the detection logic.

When the traffic matches a suspicious pattern, the system produces a security alert. That alert becomes the input to the investigation stage.

This separation matters.

I don't want the LLM responsible for deciding what every packet means. Network monitoring and detection should remain explicit and inspectable. The LLM is more useful after the system has identified something worth investigating.

The architecture therefore looks roughly like this:

```text
Live Network Traffic
        |
        v
   Scapy Sniffer
        |
        v
Traffic Analysis / Detection
        |
        v
   Security Alert
        |
        v
    LLM Analysis
        |
        +------> Hindsight Memory
        |              |
        |              v
        +------< Previous Incident Context
        |
        v
 Investigation Result
```

Hindsight sits alongside the investigation workflow rather than replacing the detection system.

That distinction became one of the most useful design decisions in the project.

## Why memory changes the investigation

An LLM is good at reasoning about the information you give it.

It is not automatically a database of everything your security system has previously observed.

That means I needed a way to preserve useful incident context outside the immediate LLM conversation.

This is where I integrated [Hindsight GitHub](https://github.com/vectorize-io/hindsight) and the [Hindsight documentation](https://hindsight.vectorize.io/).

The basic idea is simple:

1. Detect suspicious activity.
2. Investigate the alert.
3. Retain useful incident information.
4. Retrieve relevant information when similar activity appears later.
5. Give the investigation additional historical context.

The important part is that memory is not just a transcript archive.

For a security agent, useful memory can include the characteristics of previous incidents, relevant identifiers, investigation findings, and relationships between recurring events.

That makes memory part of the reasoning workflow.

## Before memory: isolated alerts

Consider a simplified sequence.

The monitoring system detects suspicious traffic associated with an address.

The LLM receives something like:

```text
Suspicious network activity detected.

Source: <source>
Destination: <destination>
Protocol: <protocol>
Observed behavior: <traffic details>
```

The model can analyze the current event.

It can explain what the behavior may indicate, identify relevant evidence, and suggest what an analyst should investigate.

But if the same source appears again later, the new investigation does not automatically have the previous context.

The two events remain separate.

This is a common pattern when adding an LLM to an existing application: the model is intelligent, but the application around it has no durable memory.

## After memory: incidents become connected

With Hindsight integrated, the workflow becomes different.

After investigating an event, the system can retain relevant information about it.

When a later event arrives, the agent can retrieve relevant historical context before continuing the investigation.

Conceptually:

```text
Previous incident
       |
       v
   Hindsight
       |
       | recall
       v
New security alert
       |
       v
LLM investigation
       |
       v
Context-aware result
```

Now the second investigation has something the first one did not: history.

For example, if suspicious activity associated with the same source appears again, the agent can consider the previous incident instead of treating the new event as completely independent.

This is where I found the distinction between an LLM application and an agent with memory particularly useful.

The model itself did not suddenly become a better network detector.

The surrounding system became better at preserving context.

For more background on the broader concept, the [Vectorize guide to agent memory](https://vectorize.io/what-is-agent-memory) explains the role of persistent memory in agent systems.

## Keeping detection separate from reasoning

One design choice I would keep is the separation between deterministic detection and LLM reasoning.

Network security has plenty of information that should remain explicit.

If a packet arrives, I can inspect its protocol, addresses, ports, timing, and other available properties directly.

That makes the detection layer easier to understand and test.

The LLM then receives a structured security event rather than being asked to interpret an entire raw packet stream.

This also makes the architecture easier to reason about:

```text
Packets
  ↓
Rules / Detection
  ↓
Alert
  ↓
LLM
  ↓
Explanation
  ↓
Memory
```

The LLM is therefore an investigation component, not the sole source of truth for packet-level detection.

That boundary also makes it easier to test the system using controlled attack simulations.

## Testing the complete pipeline

A security monitoring system cannot be validated simply by checking whether the Python program starts.

I need to know whether suspicious traffic actually travels through the complete pipeline.

That is why the project includes controlled attack simulation as part of testing.

The test flow is:

```text
Controlled Test Traffic
        ↓
Packet Capture
        ↓
Detection
        ↓
Alert
        ↓
LLM Investigation
        ↓
Memory
```

This makes it possible to verify the individual stages and, more importantly, verify that they work together.

The interesting test is not just:

> Did the sniffer capture a packet?

It is:

> Did suspicious activity become an alert, get investigated, and become useful context for a future investigation?

That is a much more meaningful test of the agent architecture.

## What I learned building it

### 1. Memory is an application feature, not just an LLM feature

Adding a language model does not automatically give an application memory.

The application needs to decide what information is worth retaining, when to retain it, and when previous information is relevant.

Hindsight gave me the infrastructure for that persistent memory layer, but the surrounding security workflow still matters.

### 2. Detection and explanation should have different responsibilities

I found it useful to keep packet-level monitoring and detection explicit while using the LLM for investigation.

That makes the system easier to reason about and avoids expecting a language model to perform a job that traditional network analysis can handle more directly.

### 3. Historical context changes the value of an alert

An isolated alert tells me about an event.

A sequence of related alerts can tell me about behavior.

Persistent memory helps bridge that gap.

That is especially relevant for security because suspicious activity often makes more sense when viewed across multiple events rather than one packet or one alert.

### 4. Testing needs to include the agent workflow

It is easy to test individual functions.

It is harder to test whether detection, investigation, and memory actually form a useful loop.

The controlled attack simulations helped frame the system as an end-to-end pipeline rather than a collection of independent components.

### 5. Memory does not remove the need for an analyst

Persistent memory can provide context, but it does not turn every retrieved event into a confirmed security incident.

The system still needs careful detection logic, useful context, and human review of important security decisions.

That is an important boundary for an AI-assisted SOC system.

## Where I would take it next

The architecture leaves several obvious areas for further development.

The detection layer can become more sophisticated without changing the memory architecture.

The investigation layer can also become more structured, with consistent incident summaries and investigation outputs.

Most importantly, the memory layer can become increasingly useful as the system accumulates relevant incident history.

That creates an interesting feedback loop:

```text
More investigations
       ↓
More useful incident memory
       ↓
More historical context
       ↓
Better-informed future investigations
```

The challenge is making sure that the memory remains relevant and useful rather than simply becoming a large collection of old alerts.

That is a problem I would rather solve through explicit memory design and retrieval behavior than by simply increasing the amount of information sent to the LLM.

## The main takeaway

The most interesting part of this project was not putting an LLM behind a network alert.

It was connecting the alert to memory.

Scapy gives the system visibility into live traffic. Detection logic turns traffic into security events. The LLM helps investigate those events. Hindsight connects investigations across time.

That changes the basic question the agent can answer.

Instead of only asking:

> “What is happening right now?”

the system can work toward:

> “What is happening now, and what do I already know about activity like this?”

For a SOC agent, that difference is significant.

The LLM provides reasoning. The network monitor provides evidence. Hindsight provides continuity.

Together, those three pieces form the foundation of the security agent I wanted to build.
