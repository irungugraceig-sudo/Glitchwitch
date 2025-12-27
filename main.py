# GlitchWitch v2.0 - XR Network Interpreter
# Advanced network analysis for VR/XR performance optimization
# Developed by Irungu Grace - Northeastern University XR Lab

from fastapi import FastAPI, UploadFile, File, Form
from fastapi.responses import HTMLResponse, FileResponse
import os
from dotenv import load_dotenv
import anthropic
from fpdf import FPDF
from datetime import datetime

# Load environment variables
load_dotenv()

# Import our analyzer
from analyzer import PacketAnalyzer

# Create our app
app = FastAPI(title="GlitchWitch", version="2.0")

# Initialize analyzer
analyzer = PacketAnalyzer()

# Initialize Claude client
claude = anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))

# Store latest analysis for PDF export
latest_analysis = {}


@app.get("/", response_class=HTMLResponse)
def home():
    """Serve the dashboard"""
    with open("templates/dashboard.html", "r", encoding="utf-8") as f:
        return f.read()


@app.post("/analyze")
async def analyze_capture(
    file: UploadFile = File(...),
    wifi_signal: str = Form(default=""),
    wifi_channel: str = Form(default=""),
    wifi_frequency: str = Form(default=""),
    wifi_noise: str = Form(default="")
):
    """Analyze an uploaded Wireshark CSV with optional WiFi data"""
    global latest_analysis
    
    temp_path = f"temp_{file.filename}"
    with open(temp_path, "wb") as f:
        content = await file.read()
        f.write(content)
    
    try:
        # Load and analyze
        analyzer.load_csv(temp_path)
        
        # Get all analysis data
        summary = analyzer.get_summary()
        protocols = analyzer.get_protocol_breakdown()
        top_talkers = analyzer.get_top_talkers(10)
        conversations = analyzer.get_conversations(10)
        timeline = analyzer.get_traffic_timeline()
        bandwidth = analyzer.get_bandwidth_timeline()
        vr_analysis = analyzer.get_vr_analysis()
        
        # Process WiFi data if provided
        wifi_data = None
        if wifi_signal:
            wifi_data = {
                "signal_dbm": wifi_signal,
                "channel": wifi_channel,
                "frequency": wifi_frequency,
                "noise": wifi_noise,
                "quality": get_wifi_quality(wifi_signal)
            }
            vr_analysis = adjust_score_for_wifi(vr_analysis, wifi_data)
        
        # Generate alerts
        alerts = generate_alerts(vr_analysis, wifi_data)
        
        # Generate AI explanation
        ai_explanation = generate_ai_explanation(summary, protocols, vr_analysis, wifi_data)
        
        # Clean up temp file
        os.remove(temp_path)
        
        # Store for PDF export
        latest_analysis = {
            "timestamp": datetime.now().isoformat(),
            "summary": summary,
            "protocols": protocols,
            "top_talkers": top_talkers,
            "conversations": conversations,
            "vr_score": vr_analysis['vr_score'],
            "grade": vr_analysis['grade'],
            "vr_analysis": vr_analysis,
            "wifi_data": wifi_data,
            "alerts": alerts,
            "ai_explanation": ai_explanation
        }
        
        return {
            "summary": summary,
            "protocols": protocols,
            "top_talkers": top_talkers,
            "conversations": conversations,
            "timeline": timeline,
            "bandwidth": bandwidth,
            "vr_score": vr_analysis['vr_score'],
            "grade": vr_analysis['grade'],
            "vr_analysis": vr_analysis,
            "wifi_data": wifi_data,
            "alerts": alerts,
            "ai_explanation": ai_explanation
        }
    
    except Exception as e:
        if os.path.exists(temp_path):
            os.remove(temp_path)
        return {"error": str(e)}


def get_wifi_quality(signal_str):
    """Determine WiFi quality from signal strength"""
    try:
        signal = int(signal_str.replace('dBm', '').replace('-', '-').strip())
        if signal > -50:
            return {"rating": "Excellent", "score": 100, "color": "#00ff00"}
        elif signal > -60:
            return {"rating": "Good", "score": 80, "color": "#00ffff"}
        elif signal > -70:
            return {"rating": "Fair", "score": 60, "color": "#ffff00"}
        elif signal > -80:
            return {"rating": "Weak", "score": 40, "color": "#ff8800"}
        else:
            return {"rating": "Poor", "score": 20, "color": "#ff0000"}
    except:
        return {"rating": "Unknown", "score": 50, "color": "#888888"}


def adjust_score_for_wifi(vr_analysis, wifi_data):
    """Adjust VR score based on WiFi conditions"""
    if not wifi_data:
        return vr_analysis
    
    quality = wifi_data.get('quality', {})
    quality_score = quality.get('score', 50)
    
    # Adjust score based on WiFi quality
    adjustment = (quality_score - 70) / 5  # -10 to +6 adjustment
    vr_analysis['vr_score'] = max(0, min(100, vr_analysis['vr_score'] + adjustment))
    
    # Update grade
    score = vr_analysis['vr_score']
    if score >= 90:
        vr_analysis['grade'] = 'A'
    elif score >= 80:
        vr_analysis['grade'] = 'B'
    elif score >= 60:
        vr_analysis['grade'] = 'C'
    elif score >= 40:
        vr_analysis['grade'] = 'D'
    else:
        vr_analysis['grade'] = 'F'
    
    vr_analysis['wifi_adjusted'] = True
    return vr_analysis


def generate_alerts(vr_analysis, wifi_data=None):
    """Generate comprehensive alerts from analysis"""
    alerts = []
    
    jitter = vr_analysis.get('jitter', {})
    retrans = vr_analysis.get('retransmissions', {})
    anomalies = vr_analysis.get('anomalies', {})
    
    # Jitter alerts
    if jitter.get('jitter_rating') == 'bad':
        alerts.append({
            "level": "bad",
            "message": f"High jitter detected ({jitter.get('avg_jitter_ms', 0):.2f}ms avg) - VR will stutter and may cause motion sickness"
        })
    elif jitter.get('jitter_rating') == 'warning':
        alerts.append({
            "level": "warning",
            "message": f"Moderate jitter ({jitter.get('avg_jitter_ms', 0):.2f}ms avg) - May cause occasional VR issues"
        })
    
    # Critical jitter spikes
    critical_spikes = jitter.get('critical_spikes', 0)
    if critical_spikes > 0:
        alerts.append({
            "level": "bad",
            "message": f"Found {critical_spikes} critical timing spikes - These will cause noticeable frame drops"
        })
    
    # Timing spikes
    spike_count = jitter.get('spike_count', 0)
    if spike_count > 50:
        alerts.append({
            "level": "warning",
            "message": f"Found {spike_count} timing spikes throughout capture - Network inconsistency detected"
        })
    
    # Retransmission alerts
    if retrans.get('rating') == 'bad':
        alerts.append({
            "level": "bad",
            "message": f"High retransmission rate ({retrans.get('rate_percent', 0):.1f}%) - Causing significant latency"
        })
    elif retrans.get('rating') == 'warning':
        alerts.append({
            "level": "warning",
            "message": f"Moderate retransmissions ({retrans.get('count', 0)} packets, {retrans.get('rate_percent', 0):.1f}%)"
        })
    
    # Duplicate ACKs and out-of-order
    dup_acks = retrans.get('dup_acks', 0)
    ooo = retrans.get('out_of_order', 0)
    if dup_acks > 50 or ooo > 20:
        alerts.append({
            "level": "warning",
            "message": f"Network congestion indicators: {dup_acks} duplicate ACKs, {ooo} out-of-order packets"
        })
    
    # Anomaly alerts
    if anomalies.get('rating') == 'bad':
        alerts.append({
            "level": "bad",
            "message": f"Traffic instability detected ({anomalies.get('anomaly_count', 0)} anomalies, {anomalies.get('critical_anomalies', 0)} critical)"
        })
    elif anomalies.get('rating') == 'warning':
        alerts.append({
            "level": "warning",
            "message": f"Some traffic irregularities found ({anomalies.get('anomaly_count', 0)} anomalies)"
        })
    
    # WiFi alerts
    if wifi_data:
        quality = wifi_data.get('quality', {})
        rating = quality.get('rating', 'Unknown')
        if rating in ['Poor', 'Weak']:
            alerts.append({
                "level": "bad",
                "message": f"Weak WiFi signal ({wifi_data.get('signal_dbm')} dBm) - Move closer to router or reduce interference"
            })
        elif rating == 'Fair':
            alerts.append({
                "level": "warning",
                "message": f"Moderate WiFi signal ({wifi_data.get('signal_dbm')} dBm) - Consider repositioning for better VR experience"
            })
    
    # Good news
    score = vr_analysis.get('vr_score', 0)
    if score >= 80 and len(alerts) == 0:
        alerts.append({
            "level": "good",
            "message": "Excellent! Network conditions are optimal for VR experiences"
        })
    elif score >= 80:
        alerts.insert(0, {
            "level": "good",
            "message": f"Overall VR score: {score}/100 (Grade {vr_analysis.get('grade', '?')}) - Good for most VR applications"
        })
    elif score >= 60:
        alerts.insert(0, {
            "level": "warning",
            "message": f"VR score: {score}/100 (Grade {vr_analysis.get('grade', '?')}) - Some issues expected during VR use"
        })
    
    return alerts


def generate_ai_explanation(summary, protocols, vr_analysis, wifi_data=None):
    """Use Claude to generate witchy but professional analysis"""
    
    wifi_section = ""
    if wifi_data and wifi_data.get('signal_dbm'):
        quality = wifi_data.get('quality', {})
        wifi_section = f"""
WIFI CONDITIONS:
- Signal Strength: {wifi_data.get('signal_dbm', 'N/A')} dBm
- Quality Rating: {quality.get('rating', 'Unknown')}
- Channel: {wifi_data.get('channel', 'N/A')}
- Frequency: {wifi_data.get('frequency', 'N/A')} GHz
- Interference Level: {wifi_data.get('noise', 'N/A')}
"""
    
    jitter = vr_analysis.get('jitter', {})
    retrans = vr_analysis.get('retransmissions', {})
    anomalies = vr_analysis.get('anomalies', {})
    protocol_health = vr_analysis.get('protocol_health', {})
    
    # Get sample problem data
    spike_samples = jitter.get('jitter_spikes', [])[:5]
    retrans_samples = retrans.get('samples', [])[:5]
    anomaly_samples = anomalies.get('anomalies', [])[:5]
    
    prompt = f"""You are GlitchWitch, a mystical but technically brilliant AI assistant who analyzes network captures for VR/XR performance. 

Your personality:
- You have subtle magical flair - you "sense" issues and "divine" problems
- You occasionally call packets "digital spirits" and problems "hexes" on the network
- But you're ALWAYS technically accurate, specific, and actionable
- You explain complex concepts simply
- You provide real recommendations based on the data

Analyze this network capture data:

=== CAPTURE OVERVIEW ===
- Total packets: {summary.get('total_packets', 0):,}
- Duration: {summary.get('duration_seconds', 0)} seconds
- Throughput: {summary.get('packets_per_second', 0):.2f} packets/sec
- Bandwidth: {summary.get('mbps', 0):.2f} Mbps
- Average packet size: {summary.get('avg_packet_size', 0):.2f} bytes
- Unique conversations: {summary.get('unique_conversations', 0)}

=== PROTOCOL BREAKDOWN ===
{chr(10).join([f"- {proto}: {data['percentage']}% ({data['count']:,} packets, avg {data['avg_size']:.0f} bytes)" for proto, data in list(protocols.items())[:7]])}

Protocol Health: {protocol_health.get('recommendation', 'N/A')}
Streaming-friendly traffic: {protocol_health.get('streaming_friendly_percent', 0):.1f}%

=== VR READINESS ===
- Score: {vr_analysis.get('vr_score', 0)}/100 (Grade: {vr_analysis.get('grade', '?')})
- Verdict: {vr_analysis.get('verdict', 'Unknown')}

=== JITTER ANALYSIS ===
- Average Jitter: {jitter.get('avg_jitter_ms', 0):.2f} ms
- Maximum Jitter: {jitter.get('max_jitter_ms', 0):.2f} ms
- 95th Percentile: {jitter.get('p95_jitter_ms', 0):.2f} ms
- 99th Percentile: {jitter.get('p99_jitter_ms', 0):.2f} ms
- Total Timing Spikes: {jitter.get('spike_count', 0)}
- Critical Spikes: {jitter.get('critical_spikes', 0)}
- Rating: {jitter.get('jitter_rating', 'unknown').upper()}

Top Timing Spikes:
{chr(10).join([f"  - Packet #{s.get('packet_no')}: {s.get('gap_ms', 0):.1f}ms delay at t={s.get('time', 0):.2f}s ({s.get('severity')})" for s in spike_samples]) if spike_samples else "  None detected"}

=== RETRANSMISSION ANALYSIS ===
- Total Retransmissions: {retrans.get('count', 0)}
- Retransmission Rate: {retrans.get('rate_percent', 0):.2f}%
- Duplicate ACKs: {retrans.get('dup_acks', 0)}
- Out-of-Order Packets: {retrans.get('out_of_order', 0)}
- Rating: {retrans.get('rating', 'unknown').upper()}

Sample Retransmissions:
{chr(10).join([f"  - Packet #{r.get('packet_no')} at t={r.get('time', 0):.2f}s: {r.get('source', '')[:20]} -> {r.get('destination', '')[:20]}" for r in retrans_samples]) if retrans_samples else "  None detected"}

=== TRAFFIC STABILITY ===
- Average: {anomalies.get('avg_pps', 0):.2f} packets/sec
- Std Deviation: {anomalies.get('std_dev', 0):.2f}
- Range: {anomalies.get('min_pps', 0)} to {anomalies.get('max_pps', 0)} packets/sec
- Total Anomalies: {anomalies.get('anomaly_count', 0)}
- Critical Anomalies: {anomalies.get('critical_anomalies', 0)}
- Spikes: {anomalies.get('spike_count', 0)} | Drops: {anomalies.get('drop_count', 0)}
- Rating: {anomalies.get('rating', 'unknown').upper()}

Sample Anomalies:
{chr(10).join([f"  - Second {a.get('second')}: {a.get('packets')} pkts ({a.get('type')}, {a.get('severity')})" for a in anomaly_samples]) if anomaly_samples else "  None detected"}
{wifi_section}

=== YOUR ANALYSIS STRUCTURE ===

Write a detailed analysis with these sections:

**OVERVIEW** (2-3 sentences with subtle witch flavor)
Start with what you sensed/divined about this network capture.

**JITTER & TIMING** (detailed paragraph)
- Explain what the jitter numbers mean for VR (under 5ms good, 5-15ms warning, over 15ms bad)
- Reference specific problematic timestamps if any critical spikes
- Explain impact: high jitter = motion sickness, controller lag, visual stuttering

**PACKET LOSS & RETRANSMISSIONS** (detailed paragraph)
- Explain the retransmission rate impact (under 1% good, 1-3% warning, over 3% bad)
- Mention duplicate ACKs and out-of-order packets if significant
- Impact: retransmissions = added latency, rubber-banding, delayed responses

**TRAFFIC PATTERNS** (detailed paragraph)
- Discuss stability of the traffic flow
- Note any significant spikes or drops
- Impact: unstable traffic = inconsistent frame delivery

**PROTOCOL INSIGHTS** (brief paragraph)
- Comment on UDP vs TCP ratio
- VR streaming prefers UDP/QUIC for low-latency delivery
- Heavy TCP might indicate congestion or retransmission overhead

{"**WIFI ASSESSMENT** (paragraph) - Analyze the signal strength and give specific recommendations" if wifi_data else ""}

**RECOMMENDATIONS** (numbered list of 4-6 specific, actionable items)

**CLOSING** (1-2 sentences, witchy sign-off)

Sign off as: "-- GlitchWitch, Guardian of Immersive Realms"
"""

    try:
        message = claude.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=2500,
            messages=[{"role": "user", "content": prompt}]
        )
        return message.content[0].text
    except Exception as e:
        return f"The spirits are unclear... (AI analysis unavailable: {str(e)})\n\nTry checking your API key and credits at console.anthropic.com"


@app.get("/export-pdf")
def export_pdf():
    """Export the latest analysis as a professional PDF report"""
    global latest_analysis
    
    if not latest_analysis:
        return {"error": "No analysis to export. Upload a capture first."}
    
    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    
    # Page 1: Cover and Summary
    pdf.add_page()
    
    # Header
    pdf.set_font("Helvetica", "B", 32)
    pdf.set_text_color(102, 0, 153)
    pdf.cell(0, 25, "GlitchWitch", ln=True, align="C")
    
    pdf.set_font("Helvetica", "", 14)
    pdf.set_text_color(100, 100, 100)
    pdf.cell(0, 8, "XR Network Analysis Report", ln=True, align="C")
    pdf.cell(0, 8, f"Generated: {datetime.now().strftime('%B %d, %Y at %H:%M')}", ln=True, align="C")
    pdf.ln(15)
    
    # VR Score Box
    score = latest_analysis.get('vr_score', 0)
    grade = latest_analysis.get('grade', '?')
    
    if score >= 80:
        pdf.set_fill_color(0, 150, 0)
        status = "EXCELLENT"
    elif score >= 60:
        pdf.set_fill_color(0, 150, 150)
        status = "GOOD"
    elif score >= 40:
        pdf.set_fill_color(200, 150, 0)
        status = "FAIR"
    else:
        pdf.set_fill_color(200, 0, 0)
        status = "POOR"
    
    pdf.set_font("Helvetica", "B", 18)
    pdf.set_text_color(255, 255, 255)
    pdf.cell(0, 18, f"    VR READINESS: {score}/100  |  Grade: {grade}  |  {status}", ln=True, fill=True)
    pdf.ln(10)
    
    # Summary Section
    pdf.set_text_color(0, 0, 0)
    pdf.set_font("Helvetica", "B", 14)
    pdf.set_fill_color(240, 240, 240)
    pdf.cell(0, 10, "  CAPTURE SUMMARY", ln=True, fill=True)
    pdf.ln(3)
    
    pdf.set_font("Helvetica", "", 11)
    summary = latest_analysis.get('summary', {})
    
    col1 = [
        f"Total Packets: {summary.get('total_packets', 0):,}",
        f"Duration: {summary.get('duration_seconds', 0)} seconds",
        f"Throughput: {summary.get('packets_per_second', 0):.2f} pkts/sec",
        f"Bandwidth: {summary.get('mbps', 0):.2f} Mbps"
    ]
    col2 = [
        f"Avg Packet Size: {summary.get('avg_packet_size', 0):.0f} bytes",
        f"Total Data: {summary.get('total_mb', 0):.2f} MB",
        f"Unique Sources: {summary.get('unique_sources', 0)}",
        f"Unique Destinations: {summary.get('unique_destinations', 0)}"
    ]
    
    for i in range(len(col1)):
        pdf.cell(95, 7, f"    {col1[i]}", ln=False)
        pdf.cell(95, 7, f"    {col2[i]}", ln=True)
    pdf.ln(5)
    
    # VR Analysis Section
    pdf.set_font("Helvetica", "B", 14)
    pdf.cell(0, 10, "  VR PERFORMANCE METRICS", ln=True, fill=True)
    pdf.ln(3)
    
    vr = latest_analysis.get('vr_analysis', {})
    jitter = vr.get('jitter', {})
    retrans = vr.get('retransmissions', {})
    anomalies = vr.get('anomalies', {})
    
    pdf.set_font("Helvetica", "B", 11)
    pdf.cell(0, 7, "    Jitter Analysis:", ln=True)
    pdf.set_font("Helvetica", "", 10)
    pdf.cell(0, 6, f"        Average: {jitter.get('avg_jitter_ms', 0):.2f} ms  |  Max: {jitter.get('max_jitter_ms', 0):.2f} ms  |  P95: {jitter.get('p95_jitter_ms', 0):.2f} ms", ln=True)
    pdf.cell(0, 6, f"        Timing Spikes: {jitter.get('spike_count', 0)} ({jitter.get('critical_spikes', 0)} critical)  |  Rating: {jitter.get('jitter_rating', 'N/A').upper()}", ln=True)
    pdf.ln(2)
    
    pdf.set_font("Helvetica", "B", 11)
    pdf.cell(0, 7, "    Retransmission Analysis:", ln=True)
    pdf.set_font("Helvetica", "", 10)
    pdf.cell(0, 6, f"        Count: {retrans.get('count', 0)}  |  Rate: {retrans.get('rate_percent', 0):.2f}%  |  Rating: {retrans.get('rating', 'N/A').upper()}", ln=True)
    pdf.cell(0, 6, f"        Duplicate ACKs: {retrans.get('dup_acks', 0)}  |  Out-of-Order: {retrans.get('out_of_order', 0)}", ln=True)
    pdf.ln(2)
    
    pdf.set_font("Helvetica", "B", 11)
    pdf.cell(0, 7, "    Traffic Stability:", ln=True)
    pdf.set_font("Helvetica", "", 10)
    pdf.cell(0, 6, f"        Average: {anomalies.get('avg_pps', 0):.2f} pkts/sec  |  Std Dev: {anomalies.get('std_dev', 0):.2f}", ln=True)
    pdf.cell(0, 6, f"        Anomalies: {anomalies.get('anomaly_count', 0)} ({anomalies.get('critical_anomalies', 0)} critical)  |  Rating: {anomalies.get('rating', 'N/A').upper()}", ln=True)
    pdf.ln(5)
    
    # WiFi Section if available
    wifi = latest_analysis.get('wifi_data')
    if wifi and wifi.get('signal_dbm'):
        pdf.set_font("Helvetica", "B", 14)
        pdf.cell(0, 10, "  WIFI CONDITIONS", ln=True, fill=True)
        pdf.ln(3)
        pdf.set_font("Helvetica", "", 11)
        quality = wifi.get('quality', {})
        pdf.cell(0, 7, f"    Signal: {wifi.get('signal_dbm')} dBm ({quality.get('rating', 'Unknown')})", ln=True)
        pdf.cell(0, 7, f"    Channel: {wifi.get('channel', 'N/A')}  |  Frequency: {wifi.get('frequency', 'N/A')} GHz", ln=True)
        pdf.cell(0, 7, f"    Interference: {wifi.get('noise', 'N/A')}", ln=True)
        pdf.ln(5)
    
    # Alerts Section
    pdf.set_font("Helvetica", "B", 14)
    pdf.cell(0, 10, "  ALERTS & FINDINGS", ln=True, fill=True)
    pdf.ln(3)
    pdf.set_font("Helvetica", "", 10)
    
    for alert in latest_analysis.get('alerts', [])[:10]:
        level = alert.get('level', '')
        if level == 'bad':
            pdf.set_text_color(180, 0, 0)
            prefix = "[!]"
        elif level == 'warning':
            pdf.set_text_color(180, 120, 0)
            prefix = "[*]"
        else:
            pdf.set_text_color(0, 130, 0)
            prefix = "[+]"
        
        message = alert.get('message', '')[:100]
        pdf.cell(0, 6, f"    {prefix} {message}", ln=True)
    
    pdf.set_text_color(0, 0, 0)
    
    # Page 2: AI Analysis
    pdf.add_page()
    pdf.set_font("Helvetica", "B", 14)
    pdf.set_fill_color(240, 240, 240)
    pdf.cell(0, 10, "  GLITCHWITCH AI ANALYSIS", ln=True, fill=True)
    pdf.ln(5)
    
    pdf.set_font("Helvetica", "", 10)
    ai_text = latest_analysis.get('ai_explanation', 'No AI analysis available')
    
    # Clean text for PDF compatibility
    ai_text = ai_text.encode('latin-1', 'replace').decode('latin-1')
    ai_text = ai_text.replace('**', '').replace('--', '-')
    
    pdf.multi_cell(0, 5, ai_text)
    
    # Footer on last page
    pdf.ln(10)
    pdf.set_font("Helvetica", "B", 11)
    pdf.set_text_color(102, 0, 153)
    pdf.cell(0, 8, "GlitchWitch - XR Network Analyzer v2.0", ln=True, align="C")
    
    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(80, 80, 80)
    pdf.cell(0, 6, "Developed by Irungu", ln=True, align="C")
    pdf.cell(0, 6, "Research | XR Immersive Media Lab", ln=True, align="C")
    pdf.cell(0, 6, "Northeastern University | MS Telecommunication Networks", ln=True, align="C")
    
    # Save PDF
    pdf_path = "glitchwitch_report.pdf"
    pdf.output(pdf_path)
    
    return FileResponse(
        pdf_path,
        media_type="application/pdf",
        filename=f"GlitchWitch_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    )
