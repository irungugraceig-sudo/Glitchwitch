\# GlitchWitch



An XR network performance analyzer I built to assess whether enterprise WiFi can actually handle VR/AR applications. It parses Wireshark packet captures and tells you what's going wrong.



!\[Demo](demo.gif)



\## What It Does



\- Analyzes Wireshark CSV exports for jitter, latency, retransmissions

\- Scores network readiness for VR/AR (spoiler: most networks aren't ready)

\- Flags timing spikes and anomalies that break immersive experiences

\- Uses Claude API to explain network issues in plain language

\- Generates PDF reports



\## Built With



Python, FastAPI, Claude API, HTML/CSS



\## Background



I built this as a Research Assistant at Northeastern's XR Immersive Media Lab. We're analyzing Quest 3 headset performance on enterprise WiFi at Holmes Hall, and I needed a tool that could interpret packet captures faster than manually digging through Wireshark.



My first real coding project. Seven years in telecom deploying submarine cables across Africa, but never wrote code until now.



\## Author



Grace Irungu  

MS Telecommunication Networks, Northeastern University

