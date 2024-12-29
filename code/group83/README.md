
# Covert Channel Implementation: Packet Bursting Using IP (CSC-PB-IP)

This project implements a covert storage channel that leverages packet bursting with the IP protocol to encode and decode binary messages. The channel operates by transmitting bursts of IP packets, with different burst sizes representing binary bits.

## Overview

The covert channel consists of two primary functions:
1. **`send`**: Encodes a binary message into IP packet bursts and transmits it.
2. **`receive`**: Captures IP packet bursts, decodes them into binary bits, and reconstructs the original message.

The implementation uses `scapy` for packet crafting and sniffing.

## Features

- **Binary Message Encoding**: Messages are encoded as bursts of IP packets, with specific burst sizes representing binary `1` and `0`.
- **Message Decoding**: Captured IP bursts are decoded into binary bits and reconstructed into characters.
- **Customizable Parameters**:
  - `burst_size_1` and `burst_size_0`: Define the burst sizes for binary `1` and `0`.
  - `idle_time`: Delay between bursts to ensure proper decoding.
  - `idle_threshold`: Time threshold to detect the end of a burst during decoding.
- **Stop Condition**: The receiver stops decoding when the message ends with `"."`.

---

## Implementation

### `send` Function
The `send` function encodes a binary message into IP packet bursts and transmits it:

#### **Input Parameters**
- **`interface`**: Network interface to send packets (default: `eth0`).
- **`burst_size_1` and `burst_size_0`**: Burst sizes for binary `1` and `0`.
- **`idle_time`**: Delay between bursts (default: `0.1` seconds).
- **`log_file_name`**: Log file for the sent message (default: `"sending_log.log"`).

#### **Operation**
1. The function generates or uses a predefined binary message.
2. Each bit is encoded as a burst of IP packets:
   - **Binary `1`**: Sent as `burst_size_1` packets.
   - **Binary `0`**: Sent as `burst_size_0` packets.
3. Bursts are separated by `idle_time` to ensure accurate decoding.

### `receive` Function
The `receive` function captures IP packets and decodes the transmitted message:

#### **Input Parameters**
- **`interface`**: Network interface to listen on (default: `eth0`).
- **`burst_size_1` and `burst_size_0`**: Expected burst sizes for binary `1` and `0`. These must match the sender for consistency.
- **`idle_threshold`**: Time threshold to detect the end of a burst (default: `0.05` seconds).
- **`log_file_name`**: Log file for the received message (default: `"received_log.log"`).

#### **Operation**
1. Captures and processes incoming IP packets.
2. Identifies bursts using timing and counts the number of packets in each burst.
3. Decodes bursts into binary bits and reconstructs the message.
4. Stops decoding when the message ends with `"."`.

---

## Covert Channel Capacity

The channel's capacity was evaluated by transmitting a known binary message and measuring the time taken for its transmission:

1. A binary message of **128 bits (16 characters)** was sent.
2. The transmission duration was recorded from the first to the last packet.
3. Capacity was calculated using:
   ```
   Capacity (bps) = Total Bits / Transmission Time (seconds)
   ```
4. The observed capacity was **8.090786039468627 bits per second**.

---

## Limitations and Constraints

1. **Idle Time and Threshold**:
   - The `idle_time` and `idle_threshold` parameters must be tuned for optimal performance.
   - Higher values improve decoding accuracy but reduce channel capacity.
   - Default settings: `idle_time = 0.1 seconds`, `idle_threshold = 0.05 seconds`.

2. **Burst Sizes**:
   - Default burst sizes are:
     - `burst_size_1 = 2` for binary `1`.
     - `burst_size_0 = 1` for binary `0`.
   - Mismatched burst sizes between sender and receiver can cause decoding errors.

3. **System Overheads**:
   - Performance may vary based on the system or environment (e.g., virtualized networks or WSL).

4. **Environmental Factors**:
   - Network conditions such as latency and packet loss can affect the reliability of the covert channel.

---

## Authors
Burak Yildiz 2449049
Aydin Dogan 2380293
