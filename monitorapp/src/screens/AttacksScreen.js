import React, { useEffect, useState } from "react";
import { Text, StyleSheet, View, FlatList, TouchableOpacity } from "react-native";
import logs from "./api/logs";

const SEVERITY_LEVELS = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'];

const SEVERITY_COLORS = {
  CRITICAL: { bg: '#0a0f1e', border: '#1e3a8a', badgeBg: '#1e3a8a55', badgeText: '#93c5fd', btn: '#1e3a8a', btnActive: '#3b6fd4' },
  HIGH:     { bg: '#0c1220', border: '#1d4ed8', badgeBg: '#1d4ed855', badgeText: '#60a5fa', btn: '#1d4ed8', btnActive: '#4a7ff5' },
  MEDIUM:   { bg: '#0d1424', border: '#2563eb', badgeBg: '#2563eb55', badgeText: '#3b82f6', btn: '#2563eb', btnActive: '#5b9cf6' },
  LOW:      { bg: '#0f1828', border: '#3b82f6', badgeBg: '#3b82f655', badgeText: '#93c5fd', btn: '#3b82f6', btnActive: '#6ab4ff' },
};

const SessionTile = ({ item }) => {
  const sev = item.severity?.toUpperCase() || 'LOW';
  const colors = SEVERITY_COLORS[sev] || SEVERITY_COLORS.LOW;
  const formattedTime = item.timestamp
    ? new Date(item.timestamp * 1000).toLocaleString()
    : '—';

  return (
    <View style={[styles.tile, { backgroundColor: colors.bg, borderColor: colors.border }]}>

      <View style={styles.tileHeader}>
        <View style={styles.ipBadge}>
          <Text style={styles.ipText}>{item.ip || '—'}</Text>
        </View>
        <View style={[styles.severityBadge, { backgroundColor: colors.badgeBg }]}>
          <Text style={[styles.severityText, { color: colors.badgeText }]}>{sev}</Text>
        </View>
      </View>

      <View style={styles.field}>
        <Text style={styles.fieldLabel}>ATTACK TYPE</Text>
        <Text style={styles.fieldValue}>{item.attack_type || '—'}</Text>
      </View>

      <View style={styles.grid}>
        <View style={styles.fieldHalf}>
          <Text style={styles.fieldLabel}>TIMESTAMP</Text>
          <Text style={styles.fieldValueSm}>{formattedTime}</Text>
        </View>
        <View style={styles.fieldHalf}>
          <Text style={styles.fieldLabel}>BEHAVIOR</Text>
          <Text style={styles.fieldValueSm}>{item.behavior || '—'}</Text>
        </View>
      </View>

      <View style={styles.grid}>
        <View style={styles.fieldHalf}>
          <Text style={styles.fieldLabel}>CVSS SCORE</Text>
          <Text style={styles.fieldValueSm}>{item.cvss_score ?? '—'}</Text>
        </View>
        <View style={styles.fieldHalf}>
          <Text style={styles.fieldLabel}>CONFIDENCE</Text>
          <Text style={styles.fieldValueSm}>{item.confidence != null ? `${(item.confidence * 100).toFixed(0)}%` : '—'}</Text>
        </View>
      </View>

      {item.mitigation ? (
        <View style={styles.mitigationBox}>
          <Text style={styles.fieldLabel}>MITIGATION</Text>
          <Text style={styles.mitigationText}>{item.mitigation}</Text>
        </View>
      ) : null}

      <View style={styles.tagRow}>
        {item.mitre_technique ? (
          <View style={styles.tag}><Text style={styles.tagText}>{item.mitre_technique}</Text></View>
        ) : null}
        {item.owasp_category ? (
          <View style={styles.tag}><Text style={styles.tagText}>{item.owasp_category}</Text></View>
        ) : null}
        {item.pattern_type ? (
          <View style={styles.tag}><Text style={styles.tagText}>{item.pattern_type}</Text></View>
        ) : null}
      </View>

    </View>
  );
};

const AttacksScreen = ({ navigation }) => {
  const [allSessions, setAllSessions] = useState([]);
  const [activeFilter, setActiveFilter] = useState('CRITICAL');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const attackLogApi = async () => {
    try {
      setLoading(true);
      setError(null);
      const response = await logs.get('/attacks');
      const data = response.data;

      let sessions = [];
      if (Array.isArray(data)) {
        sessions = data;
      } else if (Array.isArray(data.attacks)) {
        sessions = data.attacks;
      } else if (data && typeof data === 'object') {
        const active = Array.isArray(data.active) ? data.active : [];
        const completed = Array.isArray(data.completed) ? data.completed : [];
        sessions = active.length || completed.length
          ? [...active, ...completed]
          : Object.entries(data).map(([key, value]) =>
              typeof value === 'object' && value !== null
                ? { session_id: key, ip: value.ip || key, ...value }
                : null
            ).filter(Boolean);
      }

      setAllSessions(sessions);
    } catch (err) {
      console.error("Error fetching attack logs:", err.message);
      setError("Failed to load attack logs.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { attackLogApi(); }, []);

  const counts = SEVERITY_LEVELS.reduce((acc, sev) => {
    acc[sev] = allSessions.filter(s => s.severity?.toUpperCase() === sev).length;
    return acc;
  }, {});

  const filtered = allSessions.filter(
    s => s.severity?.toUpperCase() === activeFilter
  );

  return (
    <View style={styles.container}>

      {/* Header */}
      <View style={styles.header}>
        <Text style={styles.headerTitle}>Attack Logs</Text>
        <Text style={styles.headerSubtitle}>{allSessions.length} total sessions</Text>
      </View>

      {/* Filter Buttons */}
      <View style={styles.filterRow}>
        {SEVERITY_LEVELS.map(sev => {
          const colors = SEVERITY_COLORS[sev];
          const isActive = activeFilter === sev;
          return (
            <TouchableOpacity
              key={sev}
              style={[
                styles.filterBtn,
                { borderColor: colors.border },
                isActive && { backgroundColor: colors.btnActive },
              ]}
              onPress={() => setActiveFilter(sev)}
            >
              <Text style={[styles.filterBtnText, isActive && { color: '#fff' }]}>
                {sev}
              </Text>
              <View style={[styles.filterCount, { backgroundColor: colors.badgeBg }]}>
                <Text style={[styles.filterCountText, { color: colors.badgeText }]}>
                  {counts[sev]}
                </Text>
              </View>
            </TouchableOpacity>
          );
        })}
      </View>

      {/* List */}
      <FlatList
        data={filtered}
        keyExtractor={(item, index) => `${item.ip}-${item.timestamp}-${index}`}
        renderItem={({ item }) => <SessionTile item={item} />}
        contentContainerStyle={styles.listContent}
        showsVerticalScrollIndicator={false}
        ListEmptyComponent={
          <View style={styles.emptyContainer}>
            <Text style={styles.emptyText}>
              {error ? error : loading ? "Loading..." : `No ${activeFilter} severity attacks.`}
            </Text>
          </View>
        }
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
        <TouchableOpacity style={styles.navButton} onPress={() => navigation.navigate('Profile')}>
          <Text style={styles.navText}>PROFILE</Text>
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

  filterRow: {
    flexDirection: 'row', gap: 8,
    paddingHorizontal: 12, paddingBottom: 12,
  },
  filterBtn: {
    flex: 1, alignItems: 'center', justifyContent: 'center',
    paddingVertical: 8, borderRadius: 10, borderWidth: 1,
    backgroundColor: '#0d1424', gap: 4,
  },
  filterBtnText: { fontSize: 10, fontWeight: '700', color: '#8b97ad', letterSpacing: 0.5 },
  filterCount: { borderRadius: 10, paddingHorizontal: 7, paddingVertical: 2 },
  filterCountText: { fontSize: 11, fontWeight: '700' },

  listContent: { padding: 12, paddingBottom: 80 },
  emptyContainer: { alignItems: "center", justifyContent: "center", paddingTop: 60 },
  emptyText: { color: "#8b97ad", fontSize: 14 },

  tile: { borderRadius: 12, padding: 14, borderWidth: 0.5, marginBottom: 12, gap: 8 },
  tileHeader: { flexDirection: "row", justifyContent: "space-between", alignItems: "center" },
  ipBadge: { paddingHorizontal: 8, paddingVertical: 4, borderRadius: 6, backgroundColor: '#1c3a6e' },
  ipText: { fontSize: 13, fontWeight: "600", color: '#5b9cf6' },
  severityBadge: { paddingHorizontal: 10, paddingVertical: 3, borderRadius: 20 },
  severityText: { fontSize: 11, fontWeight: "700", letterSpacing: 0.5 },

  field: { backgroundColor: "#0d1f3c", borderRadius: 6, padding: 8 },
  grid: { flexDirection: "row", gap: 8 },
  fieldHalf: { flex: 1, backgroundColor: "#0d1f3c", borderRadius: 6, padding: 8 },
  fieldLabel: { fontSize: 10, color: "#8b97ad", marginBottom: 3, letterSpacing: 0.5 },
  fieldValue: { fontSize: 13, color: "#e0e6f0", fontWeight: "500" },
  fieldValueSm: { fontSize: 11, color: "#e0e6f0" },

  mitigationBox: { backgroundColor: '#0a1628', borderRadius: 6, padding: 8, borderLeftWidth: 2, borderLeftColor: '#3b82f6' },
  mitigationText: { fontSize: 11, color: '#93c5fd', lineHeight: 16 },

  tagRow: { flexDirection: 'row', flexWrap: 'wrap', gap: 6 },
  tag: { backgroundColor: '#0d1f3c', borderRadius: 6, paddingHorizontal: 8, paddingVertical: 3, borderWidth: 0.5, borderColor: '#2a3a5c' },
  tagText: { fontSize: 10, color: '#5b9cf6' },

  footer: { borderTopWidth: 0.5, borderTopColor: "#ffffff15", paddingTop: 8, marginTop: 2 },
  footerText: { fontSize: 11, color: "#8b97ad" },

  bottomNav: { flexDirection: "row", backgroundColor: "#2a3038", borderTopWidth: 1, borderTopColor: "#FF6B6B", height: 60 },
  navButton: { flex: 1, justifyContent: "center", alignItems: "center" },
  navButtonActive: { borderBottomWidth: 3, borderBottomColor: "#00BFFF" },
  navText: { color: "#999", fontSize: 12, fontWeight: "600" },
  navTextActive: { color: "#00BFFF" },
});

export default AttacksScreen;