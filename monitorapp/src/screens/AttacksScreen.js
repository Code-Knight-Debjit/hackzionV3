import React, { useEffect, useState } from "react";
import { Text, StyleSheet, View, FlatList, TouchableOpacity } from "react-native";
import logs from "./api/logs";

const getSeverityColor = (severity) => {
  switch (severity?.toUpperCase()) {
    case 'CRITICAL': return { bg: '#0a0f1e', border: '#1e3a8a', badgeBg: '#1e3a8a55', badgeText: '#93c5fd' };
    case 'HIGH':     return { bg: '#0c1220', border: '#1d4ed8', badgeBg: '#1d4ed855', badgeText: '#60a5fa' };
    case 'MEDIUM':   return { bg: '#0d1424', border: '#2563eb', badgeBg: '#2563eb55', badgeText: '#3b82f6' };
    case 'LOW':      return { bg: '#0f1828', border: '#3b82f6', badgeBg: '#3b82f655', badgeText: '#93c5fd' };
    default:         return { bg: '#0f1a2e', border: '#2a3a5c', badgeBg: '#ffffff15', badgeText: '#8b97ad' };
  }
};

const SessionTile = ({ item }) => {
  const severityColors = getSeverityColor(item.severity);
  const firstSeen = new Date(item.first_seen * 1000).toLocaleString();
  const lastSeen = new Date(item.last_seen * 1000).toLocaleString();
  const eventCount = item.events?.length || 0;
  const scenarios = item.scenarios || [];

  return (
    <View style={[styles.tile, { backgroundColor: severityColors.bg, borderColor: severityColors.border }]}>

      <View style={styles.tileHeader}>
        <View style={[styles.ipBadge, { backgroundColor: '#1c3a6e' }]}>
          <Text style={[styles.ipText, { color: '#5b9cf6' }]}>{item.ip}</Text>
        </View>
        <View style={[styles.severityBadge, { backgroundColor: severityColors.badgeBg }]}>
          <Text style={[styles.severityText, { color: severityColors.badgeText }]}>
            {item.severity || 'UNKNOWN'}
          </Text>
        </View>
      </View>

      <View style={styles.field}>
        <Text style={styles.fieldLabel}>SESSION ID</Text>
        <Text style={styles.fieldValue}>{item.session_id || '—'}</Text>
      </View>

      <View style={styles.field}>
        <Text style={styles.fieldLabel}>ATTACK TYPE</Text>
        <Text style={styles.fieldValue}>{item.attack_type || '—'}</Text>
      </View>

      <View style={styles.grid}>
        <View style={styles.fieldHalf}>
          <Text style={styles.fieldLabel}>FIRST SEEN</Text>
          <Text style={styles.fieldValueSm}>{firstSeen}</Text>
        </View>
        <View style={styles.fieldHalf}>
          <Text style={styles.fieldLabel}>LAST SEEN</Text>
          <Text style={styles.fieldValueSm}>{lastSeen}</Text>
        </View>
      </View>

      <View style={styles.grid}>
        <View style={styles.fieldHalf}>
          <Text style={styles.fieldLabel}>STATUS</Text>
          <Text style={[styles.fieldValueSm, { textTransform: 'capitalize' }]}>{item.status || '—'}</Text>
        </View>
        <View style={styles.fieldHalf}>
          <Text style={styles.fieldLabel}>DURATION</Text>
          <Text style={styles.fieldValueSm}>{item.duration ? `${item.duration.toFixed(2)}s` : '—'}</Text>
        </View>
      </View>

      {scenarios.length > 0 && (
        <View style={styles.field}>
          <Text style={styles.fieldLabel}>SCENARIOS ({scenarios.length})</Text>
          <Text style={styles.fieldValueSm}>{[...new Set(scenarios)].join(', ')}</Text>
        </View>
      )}

      <View style={styles.footer}>
        <Text style={styles.footerText}>{eventCount} event{eventCount !== 1 ? 's' : ''} recorded</Text>
      </View>

    </View>
  );
};

const AttacksScreen = ({ navigation }) => {
  const [sessions, setSessions] = useState([]);
  const [summary, setSummary] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const attackLogApi = async () => {
  try {
    setLoading(true);
    setError(null);
    const response = await logs.get('/attacks');
    const data = response.data;

    console.log("Raw response:", JSON.stringify(data)); // helps debug shape

    let allSessions = [];

    if (Array.isArray(data)) {
      // Response is a flat array
      allSessions = data;
    } else if (data && typeof data === 'object') {
      const active = Array.isArray(data.active) ? data.active : [];
      const completed = Array.isArray(data.completed) ? data.completed : [];

      if (active.length || completed.length) {
        // { active: [], completed: [] } shape
        allSessions = [...active, ...completed];
      } else {
        // Might be IP-keyed dict: { "192.168.1.1": { ... } }
        allSessions = Object.entries(data).map(([key, value]) => {
          if (typeof value === 'object' && value !== null) {
            return { session_id: key, ip: value.ip || key, ...value };
          }
          return null;
        }).filter(Boolean);
      }
    }

    setSessions(allSessions);
    setSummary(data?.summary || null);
  } catch (err) {
    console.error("Error fetching attack logs:", err.message);
    setError("Failed to load attack logs.");
  } finally {
    setLoading(false);
  }
};

  useEffect(() => {
    attackLogApi();
  }, []);

  const renderEmpty = () => (
    <View style={styles.emptyContainer}>
      <Text style={styles.emptyText}>
        {error ? error : loading ? "Loading..." : "No attack logs found."}
      </Text>
    </View>
  );

  const renderHeader = () => summary ? (
    <View style={styles.summaryBar}>
      <View style={styles.summaryItem}>
        <Text style={styles.summaryValue}>{summary.total_sessions}</Text>
        <Text style={styles.summaryLabel}>TOTAL</Text>
      </View>
      <View style={styles.summaryItem}>
        <Text style={[styles.summaryValue, { color: '#f6a05b' }]}>{summary.active_count}</Text>
        <Text style={styles.summaryLabel}>ACTIVE</Text>
      </View>
      <View style={styles.summaryItem}>
        <Text style={[styles.summaryValue, { color: '#5bf6a0' }]}>{summary.completed_count}</Text>
        <Text style={styles.summaryLabel}>COMPLETED</Text>
      </View>
    </View>
  ) : null;

  return (
    <View style={styles.container}>
      <View style={styles.header}>
        <Text style={styles.headerTitle}>Attack Logs</Text>
        <Text style={styles.headerSubtitle}>
          {sessions.length} session{sessions.length !== 1 ? 's' : ''} flagged
        </Text>
      </View>

      <FlatList
        data={sessions}
        keyExtractor={(item) => item.session_id}
        renderItem={({ item }) => <SessionTile item={item} />}
        contentContainerStyle={styles.listContent}
        ListHeaderComponent={renderHeader}
        ListEmptyComponent={renderEmpty}
        showsVerticalScrollIndicator={false}
      />

      <View style={styles.bottomNav}>
        <TouchableOpacity style={styles.navButton} onPress={() => navigation.navigate('Main')}>
          <Text style={styles.navText}>HOME</Text>
        </TouchableOpacity>
        <TouchableOpacity style={[styles.navButton, styles.navButtonActive]}>
          <Text style={[styles.navText, styles.navTextActive]}>ATTACKS</Text>
        </TouchableOpacity>
        <TouchableOpacity style={styles.navButton} onPress={() => navigation.navigate('Defense')}>
          <Text style={styles.navText}>DEFENSE</Text>
        </TouchableOpacity>
        <TouchableOpacity style={styles.navButton} onPress={() => navigation.navigate('Alerts')}>
          <Text style={styles.navText}>ALERTS</Text>
        </TouchableOpacity>
      </View>
    </View>
  );
};

const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: "#10141a" },
  header: { paddingHorizontal: 16, paddingTop: 20, paddingBottom: 10 },
  headerTitle: { fontSize: 24, fontWeight: "bold", color: "#5b9cf6", marginBottom: 2 },
  headerSubtitle: { fontSize: 12, color: "#8b97ad" },
  summaryBar: { flexDirection: 'row', justifyContent: 'space-around', backgroundColor: '#1a2030', borderRadius: 10, padding: 12, marginBottom: 12 },
  summaryItem: { alignItems: 'center' },
  summaryValue: { fontSize: 20, fontWeight: 'bold', color: '#5b9cf6' },
  summaryLabel: { fontSize: 10, color: '#8b97ad', marginTop: 2, letterSpacing: 0.5 },
  listContent: { padding: 12, paddingBottom: 80 },
  emptyContainer: { alignItems: "center", justifyContent: "center", paddingTop: 60 },
  emptyText: { color: "#8b97ad", fontSize: 14 },
  tile: { borderRadius: 12, padding: 14, borderWidth: 0.5, marginBottom: 12, gap: 8 },
  tileHeader: { flexDirection: "row", justifyContent: "space-between", alignItems: "center" },
  ipBadge: { paddingHorizontal: 8, paddingVertical: 4, borderRadius: 6 },
  ipText: { fontSize: 13, fontWeight: "600" },
  severityBadge: { paddingHorizontal: 10, paddingVertical: 3, borderRadius: 20 },
  severityText: { fontSize: 11, fontWeight: "700", letterSpacing: 0.5 },
  field: { backgroundColor: "#0d1f3c", borderRadius: 6, padding: 8 },
  fieldHalf: { flex: 1, backgroundColor: "#0d1f3c", borderRadius: 6, padding: 8 },
  grid: { flexDirection: "row", gap: 8 },
  fieldLabel: { fontSize: 10, color: "#8b97ad", marginBottom: 3, letterSpacing: 0.5 },
  fieldValue: { fontSize: 13, color: "#e0e6f0", fontWeight: "500" },
  fieldValueSm: { fontSize: 11, color: "#e0e6f0" },
  footer: { borderTopWidth: 0.5, borderTopColor: "#ffffff15", paddingTop: 8, marginTop: 2 },
  footerText: { fontSize: 11, color: "#8b97ad" },
  bottomNav: { flexDirection: "row", backgroundColor: "#2a3038", borderTopWidth: 1, borderTopColor: "#FF6B6B", height: 60 },
  navButton: { flex: 1, justifyContent: "center", alignItems: "center" },
  navButtonActive: { borderBottomWidth: 3, borderBottomColor: "#00BFFF" },
  navText: { color: "#999", fontSize: 12, fontWeight: "600" },
  navTextActive: { color: "#00BFFF" },
});

export default AttacksScreen;