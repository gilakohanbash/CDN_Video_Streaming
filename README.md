# UDP Video Streaming Simulator (CSCI 353)

This project implements a UDP-based video streaming system with adaptive bitrate control and congestion handling. A custom video server sends frames to a client, which adjusts the stream based on current network conditions using congestion control algorithms.

> Developed by Gila Kohanbash and Nona Nersisyan as part of the coursework for *CSCI 353: Introduction to Internetworking* at the **University of Southern California**.

---

## Objectives

- Simulate a real-time video streaming environment over UDP
- Implement two congestion control algorithms:
  - Additive-Increase-Multiplicative-Decrease (AIMD)
  - Logarithmic Increase Rate Control (LIRC)
- Evaluate performance based on loss rates, throughput, delay, and utility

---

##Features

- **Custom Video Server & Client** — Built to simulate realistic UDP behavior.
- **Congestion Control** — Real-time adjustment of bitrate using AIMD and LIRC logic.
- **Statistics Generation** — CSV output of packet loss, goodput, delay, and other metrics.
- **Command Line Interface** — Flexible control over run parameters like bitrate, frame rate, and algorithm type.

---
