# GlitchWitch Analyzer v2.0
# Advanced Wireshark CSV analysis for VR/XR performance
# Developed by Grace Wanjiru Wanjiku - Northeastern University XR Lab

import csv
from collections import defaultdict
from datetime import datetime


class PacketAnalyzer:
    def __init__(self):
        self.packets = []
        self.protocols = defaultdict(int)
        self.sources = defaultdict(int)
        self.destinations = defaultdict(int)
        self.timeline = defaultdict(int)
        self.sizes = []
        self.conversations = defaultdict(lambda: {'packets': 0, 'bytes': 0})
        
    def load_csv(self, filepath):
        """Load and parse a Wireshark CSV export"""
        self.packets = []
        
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            reader = csv.DictReader(f)
            for row in reader:
                try:
                    packet = {
                        'no': int(row.get('No.', 0)),
                        'time': float(row.get('Time', 0)),
                        'source': row.get('Source', ''),
                        'destination': row.get('Destination', ''),
                        'protocol': row.get('Protocol', ''),
                        'length': int(row.get('Length', 0)),
                        'info': row.get('Info', '')
                    }
                    self.packets.append(packet)
                except (ValueError, KeyError):
                    continue
        
        self._analyze()
        return len(self.packets)
    
    def _analyze(self):
        """Run comprehensive analysis on loaded packets"""
        self.protocols = defaultdict(int)
        self.sources = defaultdict(int)
        self.destinations = defaultdict(int)
        self.timeline = defaultdict(int)
        self.sizes = []
        self.conversations = defaultdict(lambda: {'packets': 0, 'bytes': 0})
        
        for pkt in self.packets:
            self.protocols[pkt['protocol']] += 1
            self.sources[pkt['source']] += 1
            self.destinations[pkt['destination']] += 1
            
            second = int(pkt['time'])
            self.timeline[second] += 1
            self.sizes.append(pkt['length'])
            
            # Track conversations
            conv_key = tuple(sorted([pkt['source'], pkt['destination']]))
            self.conversations[conv_key]['packets'] += 1
            self.conversations[conv_key]['bytes'] += pkt['length']
    
    def get_protocol_breakdown(self):
        """Returns protocol distribution with detailed stats"""
        total = len(self.packets)
        if total == 0:
            return {}
        
        breakdown = {}
        for proto, count in sorted(self.protocols.items(), key=lambda x: x[1], reverse=True):
            proto_packets = [p for p in self.packets if p['protocol'] == proto]
            proto_bytes = sum(p['length'] for p in proto_packets)
            
            breakdown[proto] = {
                'count': count,
                'percentage': round((count / total) * 100, 2),
                'bytes': proto_bytes,
                'avg_size': round(proto_bytes / count, 2) if count > 0 else 0
            }
        
        return breakdown
    
    def get_top_talkers(self, n=10):
        """Returns top sources and destinations with byte counts"""
        source_bytes = defaultdict(int)
        dest_bytes = defaultdict(int)
        
        for pkt in self.packets:
            source_bytes[pkt['source']] += pkt['length']
            dest_bytes[pkt['destination']] += pkt['length']
        
        top_sources = sorted(self.sources.items(), key=lambda x: x[1], reverse=True)[:n]
        top_destinations = sorted(self.destinations.items(), key=lambda x: x[1], reverse=True)[:n]
        
        return {
            'top_sources': [
                {
                    'ip': ip, 
                    'packets': count,
                    'bytes': source_bytes[ip],
                    'avg_size': round(source_bytes[ip] / count, 2) if count > 0 else 0
                } 
                for ip, count in top_sources
            ],
            'top_destinations': [
                {
                    'ip': ip, 
                    'packets': count,
                    'bytes': dest_bytes[ip],
                    'avg_size': round(dest_bytes[ip] / count, 2) if count > 0 else 0
                } 
                for ip, count in top_destinations
            ]
        }
    
    def get_conversations(self, n=10):
        """Get top conversations between hosts"""
        sorted_convs = sorted(
            self.conversations.items(), 
            key=lambda x: x[1]['packets'], 
            reverse=True
        )[:n]
        
        return [
            {
                'host_a': conv[0][0],
                'host_b': conv[0][1],
                'packets': conv[1]['packets'],
                'bytes': conv[1]['bytes']
            }
            for conv in sorted_convs
        ]
    
    def get_traffic_timeline(self):
        """Returns packets per second with additional stats"""
        if not self.timeline:
            return []
        
        max_second = max(self.timeline.keys())
        timeline_data = []
        
        for s in range(max_second + 1):
            packets = self.timeline.get(s, 0)
            timeline_data.append({
                'second': s,
                'packets': packets
            })
        
        return timeline_data
    
    def get_bandwidth_timeline(self):
        """Returns bytes per second over time"""
        bandwidth = defaultdict(int)
        
        for pkt in self.packets:
            second = int(pkt['time'])
            bandwidth[second] += pkt['length']
        
        if not bandwidth:
            return []
        
        max_second = max(bandwidth.keys())
        return [
            {'second': s, 'bytes': bandwidth.get(s, 0)}
            for s in range(max_second + 1)
        ]
    
    def get_summary(self):
        """Returns comprehensive capture summary"""
        if not self.packets:
            return {}
        
        duration = self.packets[-1]['time'] - self.packets[0]['time']
        total_bytes = sum(self.sizes)
        
        return {
            'total_packets': len(self.packets),
            'duration_seconds': round(duration, 2),
            'total_bytes': total_bytes,
            'total_mb': round(total_bytes / (1024 * 1024), 2),
            'avg_packet_size': round(total_bytes / len(self.packets), 2),
            'packets_per_second': round(len(self.packets) / duration, 2) if duration > 0 else 0,
            'bytes_per_second': round(total_bytes / duration, 2) if duration > 0 else 0,
            'mbps': round((total_bytes * 8) / (duration * 1000000), 2) if duration > 0 else 0,
            'unique_protocols': len(self.protocols),
            'unique_sources': len(self.sources),
            'unique_destinations': len(self.destinations),
            'unique_conversations': len(self.conversations),
            'start_time': round(self.packets[0]['time'], 3),
            'end_time': round(self.packets[-1]['time'], 3)
        }

    def detect_jitter(self):
        """Analyze packet timing consistency - critical for VR"""
        if len(self.packets) < 2:
            return {"error": "Not enough packets"}
        
        gaps = []
        for i in range(1, len(self.packets)):
            gap = self.packets[i]['time'] - self.packets[i-1]['time']
            gaps.append(gap)
        
        if not gaps:
            return {}
        
        avg_gap = sum(gaps) / len(gaps)
        jitter_values = [abs(g - avg_gap) for g in gaps]
        avg_jitter = sum(jitter_values) / len(jitter_values)
        max_jitter = max(jitter_values)
        min_jitter = min(jitter_values)
        
        # Calculate percentiles
        sorted_jitter = sorted(jitter_values)
        p95_idx = int(len(sorted_jitter) * 0.95)
        p99_idx = int(len(sorted_jitter) * 0.99)
        p95_jitter = sorted_jitter[p95_idx] if p95_idx < len(sorted_jitter) else max_jitter
        p99_jitter = sorted_jitter[p99_idx] if p99_idx < len(sorted_jitter) else max_jitter
        
        # Find jitter spikes
        spike_threshold = avg_gap * 3
        spikes = []
        for i, gap in enumerate(gaps):
            if gap > spike_threshold:
                severity = 'critical' if gap > avg_gap * 10 else 'high' if gap > avg_gap * 5 else 'medium'
                spikes.append({
                    'packet_no': self.packets[i+1]['no'],
                    'time': round(self.packets[i+1]['time'], 3),
                    'gap_ms': round(gap * 1000, 2),
                    'expected_ms': round(avg_gap * 1000, 2),
                    'deviation': round((gap / avg_gap) if avg_gap > 0 else 0, 1),
                    'severity': severity
                })
        
        # Sort spikes by severity
        severity_order = {'critical': 0, 'high': 1, 'medium': 2}
        spikes.sort(key=lambda x: (severity_order.get(x['severity'], 3), -x['gap_ms']))
        
        return {
            'avg_gap_ms': round(avg_gap * 1000, 4),
            'avg_jitter_ms': round(avg_jitter * 1000, 4),
            'max_jitter_ms': round(max_jitter * 1000, 4),
            'min_jitter_ms': round(min_jitter * 1000, 4),
            'p95_jitter_ms': round(p95_jitter * 1000, 4),
            'p99_jitter_ms': round(p99_jitter * 1000, 4),
            'jitter_spikes': spikes[:30],
            'spike_count': len(spikes),
            'critical_spikes': len([s for s in spikes if s['severity'] == 'critical']),
            'high_spikes': len([s for s in spikes if s['severity'] == 'high']),
            'jitter_rating': 'good' if avg_jitter * 1000 < 5 else 'warning' if avg_jitter * 1000 < 15 else 'bad'
        }
    
    def find_retransmissions(self):
        """Find TCP retransmissions with detailed info"""
        retransmissions = []
        dup_acks = []
        out_of_order = []
        
        for pkt in self.packets:
            info = pkt['info'].lower()
            
            if 'retransmission' in info:
                retransmissions.append({
                    'packet_no': pkt['no'],
                    'time': round(pkt['time'], 3),
                    'source': pkt['source'],
                    'destination': pkt['destination'],
                    'protocol': pkt['protocol'],
                    'length': pkt['length'],
                    'type': 'retransmission',
                    'info': pkt['info'][:150]
                })
            elif 'dup ack' in info or 'duplicate ack' in info:
                dup_acks.append({
                    'packet_no': pkt['no'],
                    'time': round(pkt['time'], 3),
                    'source': pkt['source'],
                    'destination': pkt['destination'],
                    'type': 'duplicate_ack'
                })
            elif 'out-of-order' in info or 'out of order' in info:
                out_of_order.append({
                    'packet_no': pkt['no'],
                    'time': round(pkt['time'], 3),
                    'source': pkt['source'],
                    'destination': pkt['destination'],
                    'type': 'out_of_order'
                })
        
        total_tcp = self.protocols.get('TCP', 0)
        retrans_rate = (len(retransmissions) / total_tcp * 100) if total_tcp > 0 else 0
        
        # Group retransmissions by source
        retrans_by_source = defaultdict(int)
        for r in retransmissions:
            retrans_by_source[r['source']] += 1
        
        top_retrans_sources = sorted(retrans_by_source.items(), key=lambda x: x[1], reverse=True)[:5]
        
        return {
            'count': len(retransmissions),
            'rate_percent': round(retrans_rate, 2),
            'dup_acks': len(dup_acks),
            'out_of_order': len(out_of_order),
            'total_issues': len(retransmissions) + len(dup_acks) + len(out_of_order),
            'samples': retransmissions[:20],
            'top_sources': [{'ip': ip, 'count': count} for ip, count in top_retrans_sources],
            'rating': 'good' if retrans_rate < 1 else 'warning' if retrans_rate < 3 else 'bad'
        }
    
    def find_traffic_anomalies(self):
        """Find unusual traffic patterns"""
        if not self.timeline:
            return {}
        
        values = list(self.timeline.values())
        avg_pps = sum(values) / len(values)
        
        # Calculate standard deviation
        variance = sum((x - avg_pps) ** 2 for x in values) / len(values)
        std_dev = variance ** 0.5
        
        anomalies = []
        for second, count in self.timeline.items():
            if count > avg_pps + (2 * std_dev):  # Spike
                severity = 'critical' if count > avg_pps * 5 else 'high' if count > avg_pps * 3 else 'medium'
                anomalies.append({
                    'second': second,
                    'packets': count,
                    'expected': round(avg_pps, 1),
                    'deviation': round((count - avg_pps) / std_dev if std_dev > 0 else 0, 1),
                    'type': 'spike',
                    'severity': severity
                })
            elif count < avg_pps - (2 * std_dev) and avg_pps > 10:  # Drop
                severity = 'critical' if count < avg_pps * 0.1 else 'high' if count < avg_pps * 0.2 else 'medium'
                anomalies.append({
                    'second': second,
                    'packets': count,
                    'expected': round(avg_pps, 1),
                    'deviation': round((avg_pps - count) / std_dev if std_dev > 0 else 0, 1),
                    'type': 'drop',
                    'severity': severity
                })
        
        # Sort by severity then by deviation
        severity_order = {'critical': 0, 'high': 1, 'medium': 2}
        anomalies.sort(key=lambda x: (severity_order.get(x['severity'], 3), -abs(x['deviation'])))
        
        return {
            'avg_pps': round(avg_pps, 2),
            'std_dev': round(std_dev, 2),
            'max_pps': max(values),
            'min_pps': min(values),
            'anomaly_count': len(anomalies),
            'spike_count': len([a for a in anomalies if a['type'] == 'spike']),
            'drop_count': len([a for a in anomalies if a['type'] == 'drop']),
            'critical_anomalies': len([a for a in anomalies if a['severity'] == 'critical']),
            'anomalies': anomalies[:30],
            'rating': 'good' if len(anomalies) < 5 else 'warning' if len(anomalies) < 15 else 'bad'
        }
    
    def analyze_protocol_health(self):
        """Analyze health of different protocols"""
        total = len(self.packets)
        if total == 0:
            return {}
        
        udp_count = self.protocols.get('UDP', 0)
        tcp_count = self.protocols.get('TCP', 0)
        quic_count = self.protocols.get('QUIC', 0)
        icmp_count = self.protocols.get('ICMP', 0)
        
        # VR typically uses UDP for streaming
        streaming_friendly = udp_count + quic_count
        streaming_percent = (streaming_friendly / total) * 100
        
        return {
            'tcp_percent': round((tcp_count / total) * 100, 2),
            'udp_percent': round((udp_count / total) * 100, 2),
            'quic_percent': round((quic_count / total) * 100, 2),
            'icmp_percent': round((icmp_count / total) * 100, 2),
            'streaming_friendly_percent': round(streaming_percent, 2),
            'vr_optimized': streaming_percent > 30,
            'recommendation': 'Good protocol mix for VR' if streaming_percent > 30 else 'Heavy TCP usage may indicate retransmission overhead'
        }
    
    def get_vr_analysis(self):
        """Complete VR-focused analysis"""
        jitter = self.detect_jitter()
        retrans = self.find_retransmissions()
        anomalies = self.find_traffic_anomalies()
        protocol_health = self.analyze_protocol_health()
        
        score = 100
        
        # Jitter impact (most critical for VR - causes motion sickness)
        if jitter.get('jitter_rating') == 'bad':
            score -= 35
        elif jitter.get('jitter_rating') == 'warning':
            score -= 15
        
        # Critical jitter spikes are very bad
        critical_spikes = jitter.get('critical_spikes', 0)
        if critical_spikes > 10:
            score -= 15
        elif critical_spikes > 5:
            score -= 8
        
        # Retransmission impact
        if retrans.get('rating') == 'bad':
            score -= 25
        elif retrans.get('rating') == 'warning':
            score -= 10
        
        # Traffic stability impact
        if anomalies.get('rating') == 'bad':
            score -= 20
        elif anomalies.get('rating') == 'warning':
            score -= 10
        
        # Protocol bonus
        if protocol_health.get('vr_optimized'):
            score += 5
        
        score = max(0, min(100, score))
        
        # Determine verdict
        if score >= 90:
            verdict = "Excellent for VR! Network is well-optimized."
        elif score >= 80:
            verdict = "Good for VR. Minor issues may occur occasionally."
        elif score >= 60:
            verdict = "Fair for VR. Expect some stuttering and latency."
        elif score >= 40:
            verdict = "Poor for VR. Significant issues likely."
        else:
            verdict = "Not recommended for VR. Major network problems detected."
        
        # Determine grade
        if score >= 90:
            grade = 'A'
        elif score >= 80:
            grade = 'B'
        elif score >= 60:
            grade = 'C'
        elif score >= 40:
            grade = 'D'
        else:
            grade = 'F'
        
        return {
            'vr_score': score,
            'grade': grade,
            'verdict': verdict,
            'jitter': jitter,
            'retransmissions': retrans,
            'anomalies': anomalies,
            'protocol_health': protocol_health
        }


# Test if run directly
if __name__ == "__main__":
    analyzer = PacketAnalyzer()
    
    try:
        count = analyzer.load_csv("capture.csv")
        print(f"\n{'='*60}")
        print(f"  GLITCHWITCH ANALYSIS REPORT")
        print(f"{'='*60}\n")
        print(f"Loaded {count:,} packets\n")
        
        print("=== SUMMARY ===")
        for key, value in analyzer.get_summary().items():
            print(f"  {key}: {value}")
        
        print("\n=== VR ANALYSIS ===")
        vr = analyzer.get_vr_analysis()
        print(f"  VR Score: {vr['vr_score']}/100 (Grade: {vr['grade']})")
        print(f"  Verdict: {vr['verdict']}")
        print(f"\n  Jitter: {vr['jitter']['avg_jitter_ms']:.2f}ms avg ({vr['jitter']['jitter_rating']})")
        print(f"  Timing Spikes: {vr['jitter']['spike_count']} ({vr['jitter']['critical_spikes']} critical)")
        print(f"  Retransmissions: {vr['retransmissions']['count']} ({vr['retransmissions']['rate_percent']:.2f}%)")
        print(f"  Traffic Anomalies: {vr['anomalies']['anomaly_count']}")
        
        print(f"\n{'='*60}")
            
    except FileNotFoundError:
        print("No capture.csv found. Export one from Wireshark!")
        