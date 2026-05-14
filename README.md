# PQ-Chat

**PQ-Chat** is an ongoing project focused on building a secure, web-based messaging application. The primary goal is to implement **Post-Quantum Cryptography (PQC)** to protect communication against future quantum computing threats.

---

## Features

- **Post-Quantum Security**: Implementation of Kyber KEM for secure key encapsulation.
- **Symmetric Encryption**: Uses AES-GCM for authenticated message encryption.
- **Modern Backend Stack**: Built with Java 21 and Spring Boot.
- **Automated Quality Assurance**: Core cryptographic logic is covered by JUnit 5 tests.
- **Maven Managed**: Dependency management and build process handled via Maven.

---

## Architecture and Security

The project is designed with a focus on cryptographic agility and clean backend architecture.

- **Key Exchange**: Utilizes the Bouncy Castle library for PQC algorithms.
- **Data Integrity**: Every message is protected by a Galois/Counter Mode (GCM) tag to prevent tampering.
- **Extensibility**: The codebase is structured to allow future integration of WebSockets and different PQC standards as they evolve.

---

## Current Status

The project is currently in the **active development phase**.
- **Completed**: Core cryptographic engine, key generation, and basic Spring Boot structure.
- **In Progress**: Real-time communication protocols and message persistence.
