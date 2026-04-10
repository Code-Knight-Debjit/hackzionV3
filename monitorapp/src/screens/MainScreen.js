import React, { useEffect, useState, useRef } from "react";
import { Text, StyleSheet, View, TouchableOpacity, ScrollView } from "react-native";
import Feather from '@expo/vector-icons/Feather';
import logs from "./api/logs";

const formatUptime = (seconds) => {
  if (seconds === null) return 'Unavailable';
  const h = Math.floor(seconds / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  const s = seconds % 60;
  if (h > 0) return `${h}h ${m}m ${s}s`;
  if (m > 0) return `${m}m ${s}s`;
  return `${s}s`;
};

const MainScreen = ({ navigation }) => {
  const [serverOnline, setServerOnline] = useState(false);
  const [uptimeSeconds, setUptimeSeconds] = useState(null);
  const serverStartRef = useRef(null);
  const intervalRef = useRef(null);
  const uptimeTickRef = useRef(null);

  const highVulnAttacks = [
    { name: "SQL Injection", severity: "Critical", timestamp: "10:30" },
    { name: "XSS Attack", severity: "Critical", timestamp: "10:45" },
    { name: "Buffer Overflow", severity: "Critical", timestamp: "11:00" },
  ];

  const pingServer = async () => {
    try {
      await logs.get('/attacks');
      // Server responded
      if (!serverStartRef.current) {
        // First successful ping — record start time
        serverStartRef.current = Date.now();
        setServerOnline(true);

        // Start ticking uptime every second
        uptimeTickRef.current = setInterval(() => {
          const elapsed = Math.floor((Date.now() - serverStartRef.current) / 1000);
          setUptimeSeconds(elapsed);
        }, 1000);
      }
    } catch {
      // Server not reachable
      setServerOnline(false);
      setUptimeSeconds(null);
      serverStartRef.current = null;

      // Stop uptime ticker if server goes down
      if (uptimeTickRef.current) {
        clearInterval(uptimeTickRef.current);
        uptimeTickRef.current = null;
      }
    }
  };

  useEffect(() => {
    pingServer(); // ping immediately on mount
    intervalRef.current = setInterval(pingServer, 10000); // re-ping every 10s

    return () => {
      clearInterval(intervalRef.current);
      clearInterval(uptimeTickRef.current);
    };
  }, []);

  return (
    <View style={styles.container}>
      <View style={styles.topBar}>
        <View>
          <Text style={styles.title}>CyberPulse Dashboard</Text>
          <Text style={styles.subtitle}>Real-time server and security status</Text>
        </View>
        <TouchableOpacity style={styles.logoutButton} onPress={() => navigation.navigate('Home')}>
          <Feather name="log-out" size={22} color="#ffffff" />
        </TouchableOpacity>
      </View>

      <ScrollView contentContainerStyle={styles.scrollContent} showsVerticalScrollIndicator={false}>
        <View style={styles.statusRow}>
          <View style={styles.statusCard}>
            <Text style={styles.cardTitle}>Server Status</Text>
            <View style={styles.statusLine}>
              <View style={[styles.statusDot, { backgroundColor: serverOnline ? '#4CF786' : '#FF6B6B' }]} />
              <Text style={styles.statusText}>{serverOnline ? 'Active' : 'Offline'}</Text>
            </View>
            <Text style={styles.statusDetail}>
              Uptime: {formatUptime(uptimeSeconds)}
            </Text>
            <Text style={styles.statusDetail}>
              {serverOnline ? 'CPU threshold safe' : 'Server unreachable'}
            </Text>
          </View>
          <View style={[styles.statusCard, styles.metricsCard]}>
            <Text style={styles.cardTitle}>Security Alert</Text>
            <Text style={styles.alertValue}>{highVulnAttacks.length}</Text>
            <Text style={styles.alertLabel}>High vulnerability attacks</Text>
            <TouchableOpacity style={styles.viewButton} onPress={() => navigation.navigate('Alerts')}>
              <Text style={styles.viewButtonText}>View Alerts</Text>
            </TouchableOpacity>
          </View>
        </View>

        <View style={styles.infoCard}>
          <View style={styles.infoHeader}>
            <Text style={styles.infoTitle}>Important Notes</Text>
            <Text style={styles.infoTag}>MAINTENANCE</Text>
          </View>
          <Text style={styles.infoText}>
            There are 3 critical attacks detected by the system. Review the alert log and apply firewall rules immediately. System health is stable, but keep monitoring incoming traffic patterns.
          </Text>
        </View>

        <View style={styles.quickActions}>
          <Text style={styles.sectionTitle}>Quick Actions</Text>
          <View style={styles.actionRow}>
            <TouchableOpacity style={styles.actionButton} onPress={() => navigation.navigate('Attacks')}>
              <Feather name="shield" size={20} color="#00BFFF" />
              <Text style={styles.actionText}>Attack Logs</Text>
            </TouchableOpacity>
            <TouchableOpacity style={styles.actionButton} onPress={() => navigation.navigate('Defense')}>
              <Feather name="shield-off" size={20} color="#00BFFF" />
              <Text style={styles.actionText}>Defense Logs</Text>
            </TouchableOpacity>
          </View>
          <View style={styles.actionRowSingle}>
            <TouchableOpacity style={[styles.actionButton, styles.actionButtonFull]} onPress={() => navigation.navigate('Alerts')}>
              <Feather name="alert-circle" size={20} color="#00BFFF" />
              <Text style={styles.actionText}>Alerts</Text>
            </TouchableOpacity>
          </View>
        </View>
      </ScrollView>
    </View>
  );
};

const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: '#10141a', paddingTop: 20 },
  topBar: { flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center', padding: 20 },
  title: { color: '#FFFFFF', fontSize: 24, fontWeight: 'bold' },
  subtitle: { color: '#A0A6B5', fontSize: 14, marginTop: 6 },
  logoutButton: { width: 44, height: 44, borderRadius: 12, justifyContent: 'center', alignItems: 'center' },
  scrollContent: { paddingHorizontal: 20, paddingBottom: 30 },
  statusRow: { flexDirection: 'row', justifyContent: 'space-between', marginBottom: 20 },
  statusCard: { flex: 1, backgroundColor: '#191d26', borderRadius: 18, padding: 20, marginRight: 10, minHeight: 150 },
  metricsCard: { marginRight: 0, marginLeft: 10, backgroundColor: '#1f2735' },
  cardTitle: { color: '#A0A6B5', fontSize: 13, textTransform: 'uppercase', letterSpacing: 1, marginBottom: 16 },
  statusLine: { flexDirection: 'row', alignItems: 'center', marginBottom: 10 },
  statusDot: { width: 10, height: 10, borderRadius: 5, marginRight: 10 },
  statusText: { color: '#FFFFFF', fontSize: 18, fontWeight: '700' },
  statusDetail: { color: '#8b97ad', fontSize: 13, marginBottom: 4 },
  alertValue: { color: '#FF6B6B', fontSize: 42, fontWeight: 'bold', marginBottom: 8 },
  alertLabel: { color: '#FFFFFF', fontSize: 14, marginBottom: 18 },
  viewButton: { alignSelf: 'flex-start', backgroundColor: '#0e1726', paddingHorizontal: 16, paddingVertical: 10, borderRadius: 12 },
  viewButtonText: { color: '#00BFFF', fontSize: 13, fontWeight: '700' },
  infoCard: { backgroundColor: '#1f2735', borderRadius: 18, padding: 20, marginBottom: 20 },
  infoHeader: { flexDirection: 'row', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 },
  infoTitle: { color: '#FFFFFF', fontSize: 16, fontWeight: '700' },
  infoTag: { color: '#00BFFF', fontSize: 12, fontWeight: '700', letterSpacing: 1 },
  infoText: { color: '#8b97ad', fontSize: 14, lineHeight: 22 },
  quickActions: { marginBottom: 30 },
  sectionTitle: { color: '#FFFFFF', fontSize: 16, fontWeight: '700', marginBottom: 16 },
  actionRow: { flexDirection: 'row', justifyContent: 'space-between', marginBottom: 12 },
  actionRowSingle: { flexDirection: 'row', justifyContent: 'center', marginBottom: 12 },
  actionButton: { width: '48%', backgroundColor: '#191d26', borderRadius: 18, paddingVertical: 18, paddingHorizontal: 14, alignItems: 'center' },
  actionButtonFull: { width: '100%' },
  actionText: { color: '#FFFFFF', fontSize: 14, fontWeight: '700', marginTop: 10 },
});

export default MainScreen;