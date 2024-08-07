# Lightweight Coordinated Sampling for Dynamic Flows under Budget Constraints

## Motivation
Cyber-attacks develop and become stealthy, high-rate line-speed sampling is required to tackle evolved attacks. However, It is challenging to achieve this due to CPU and throughput bottlenecks on the switch.
The existing sampling works mainly focus on optimizing the sampling profit within limited resources on a single switch. 

If we think of this problem as similar to distributed computing, such as distributing the sampling tasks to multiple switches to relax the throughput bottlenecks, some challenges need to be addressed. 
First of all, we need to coordinate the samplings for the flows to avoid sampling duplication. 

## Key Technique and Intuition
We utilize P4-programmable switches to coordinate samplings automatically and it is robust. 
```
             Monitor
              |   \
Host1----P4_SW_1---P4_SW_2----Host2
```
In this simple scenario, the controller wants to sample every packet. 
Suppose both switches can sample and they work together to sample every packet. 
In a dummy way, the P4_SW_1 can sample the odd index packets, and the P4_SW_2 sample the even index packets. 
However, it is not robust, when packet dropping happens between P4_SW_1 and P4_SW_2. the duplicated sampling will happen after the dropping. 

For example, if packet 4 is dropped during the transition from P4_SW_1 to P4_SW_2, P4_SW_2 thinks packet 5 is packet 4 and causes continuously duplicated sampling from this point.

We aim to achieve robust automatic coordinated sampling. 
The key intuition of technique 1 is that we let P4_SW_1 tag the sampled packet. Consequently, the P4_SW_2 can tell if a packet has been sampled to avoid duplicated sampling even when packet dropping happens. 

## Coordinated Sampling Algorithm Overview

When a packet comes to a sampling switch, in the ingress pipeline, the switch checks whether this packet has been sampled or not. If yes, the algorithm resets the counter to re-initiate its local state. This can stop duplicated sampling propagation when a transmission anomaly happens. If the packet is not tagged, it goes to the next step to check whether this packet hit the sampling interval. If yes, the packet is sampled and tagged. If no, it goes to the normal forwarding table. In the egress pipeline, we design an untagging table to remove tags before the packet arrives at its destination to conceal the sampling process from users. 

## Coordinated Sampling Algorithm Overhead
Our coordinated sampling algorithm is efficient in both CPU and memory consumption. That is because the mirroring functionality does not cost CPU on programmable ASIC. For the memory, the counter only tracks packets within a round. Another parameter we call round ID assists the controller in sorting packets. For the previous motivating example, the different colors represent different round IDs. The controller can extract round IDs from the sampled packet and sort them by collecting the same round ID increasingly. 
With this design, the counter and round ID only need minimal bits to save memory.

