# QRadar 101 Challenge – Conceptual Analysis & Learning Report

**Platform:** LetsDefend.io  
**Challenge:** QRadar 101  
**Status:** Completed (Conceptual & Guided Analysis)

---

## Overview

This document summarizes the learning outcomes and analysis performed as part of the **QRadar 101 Challenge** on LetsDefend.io.  
Due to **hardware limitations and IBM QRadar licensing constraints**, a full hands-on lab deployment was not feasible on the local system.  
Instead, the challenge was completed through **guided walkthroughs, documentation study, and simulated analysis** as provided by the platform.

This approach reflects real-world constraints often faced by SOC analysts when access to licensed SIEM platforms is limited.

---

## i) Learning the Basics of IBM QRadar

Through the QRadar 101 challenge materials, the following core concepts of **IBM QRadar SIEM** were learned:

- QRadar architecture and data flow
- Difference between **Events** and **Flows**
- Role of **Log Sources** and **Event Collectors**
- Purpose of **Correlation Rules**
- Understanding **Offenses**, **Magnitude**, and **Credibility**
- High-level navigation of the QRadar console

---

## ii) Event Correlation, Log Analysis & Rule Logic Study

### Event Correlation (Conceptual)
- Studied how QRadar correlates multiple low-level events into a single offense
- Understood correlation logic based on:
  - Event frequency
  - Time windows
  - Source and destination relationships
- Learned how correlation helps reduce alert noise in SOC environments

### Log Analysis (Demonstration-Based)
- Reviewed sample event logs and screenshots provided in the challenge
- Analyzed log attributes such as:
  - Source IP
  - Destination IP
  - Event category
  - Timestamp
- Identified suspicious patterns such as repeated authentication failures

### Rule Creation (Logic-Level Understanding)
- Studied the structure of QRadar correlation rules
- Learned key rule components:
  - Test conditions
  - Thresholds
  - Time-based logic
  - Offense creation actions
- Reviewed example rules for detecting brute-force and abnormal activity

---

## iii) Challenge Completion & Progress Recording

- All QRadar 101 challenge tasks were reviewed and completed conceptually
- Followed the instructions and expected outcomes provided by LetsDefend
- Progress and learning outcomes were documented
- System and licensing limitations were transparently noted

---

## iv) Screenshots & Key Learnings

### Screenshots Used
- QRadar architecture diagrams
- Offense workflow illustrations
- Sample rule configuration screenshots from LetsDefend documentation

*(Screenshots are included as supporting learning evidence)*

---

## Key Learnings

- SIEM platforms rely on **event correlation**, not individual alerts
- Properly tuned rules are essential to reduce false positives
- Contextual analysis is critical for accurate incident detection
- QRadar requires enterprise-level infrastructure and licensing
- Conceptual understanding of detection logic is valuable even without direct deployment

---

## Conclusion

Although a full hands-on QRadar lab could not be deployed due to system and licensing constraints, the QRadar 101 challenge successfully provided a strong conceptual understanding of SIEM operations, correlation logic, and SOC workflows.  
This knowledge is directly applicable to real-world SOC environments and enterprise security monitoring.

---

## Notes

- No screenshots or results were fabricated
- All observations are based on guided materials and documentation
- This report reflects realistic constraints faced in SIEM learning environments
