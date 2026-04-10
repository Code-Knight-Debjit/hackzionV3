import React, { useEffect, useState } from "react";
import { Text, StyleSheet, View, FlatList, TouchableOpacity, Animated, SectionList } from "react-native";
import defenceapi from "./api/defenceapi";

const getSeverityColor = (severity) => {
  switch (severity?.toLowerCase()) {
    case 'critical': return { bg: '#0a2e12', border: '#1a6e30', badgeBg: '#1a6e3044', badgeText: '#5bf67c' };
    case 'high':     return { bg: '#0f2e15', border: '#1a8b35', badgeBg: '#1a8b3544', badgeText: '#7cf690' };
    case 'medium':   return { bg: '#0f2e1a', border: '#2a6e35', badgeBg: '#2a6e3544', badgeText: '#5bf67c' };
    case 'low':      return { bg: '#0f2e15', border: '#1a6e30', badgeBg: '#5bf67c22', badgeText: '#5bf67c' };
    default:         return { bg: '#0f2e15', border: '#1a6e30', badgeBg: '#5bf67c22', badgeText: '#5bf67c' };
  }
};

const PulsingDot = () => {
  const anim = React.useRef(new Animated.Value(1)).current;
  React.useEffect(() => {
    Animated.loop(
      Animated.sequence([
        Animated.timing(anim, { toValue: 0.2, duration: 800, useNativeDriver: true }),
        Animated.timing(anim, { toValue: 1, duration: 800, useNativeDriver: true }),
      ])
    ).start();
  }, []);
  return <Animated.View style={[styles.pulsingDot, { opacity: anim }]} />;
};

const DefendedIpTile = ({ ip, data }) => {
  const firstSeen = new Date(data.first_seen * 1000).toLocaleString();
  const lastSeen = new Date(data.last_seen * 1000).toLocaleString();
  const eventCount = data.events?.length || 0;

  return (
    <View style={styles.defendedTile}>
      <View style={styles.defendedBanner}>
        <Text style={styles.defendedBannerText}>DEFENDED</Text>
      </View>

      <View style={styles.tileHeader}>
        <View style={styles.ipBadgeGreen}>
          <Text style={styles.ipTextGreen}>{ip}</Text>
        </View>
        <View style={styles.severityBadgeGreen}>
          <Text style={styles.severityTextGreen}>{data.severity || 'UNKNOWN'}</Text>
        </View>
      </View>

      <View style={styles.field}>
        <Text style={styles.fieldLabel}>ATTACK TYPE</Text>
        <Text style={styles.fieldValue}>{data.attack_type || '—'}</Text>
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

      <View style={styles.footer}>
        <Text style={styles.footerTextGreen}>{eventCount} event{eventCount !== 1 ? 's' : ''} blocked</Text>
      </View>
    </View>
  );
};

const DefenseTile = ({ item }) => {
  const colors = getSeverityColor(item.severity);
  const formattedTime = item.ts ? new Date(item.ts * 1000).toLocaleString() : '—';

  return (
    <View style={[styles.tile, { backgroundColor: colors.bg, borderColor: colors.border }]}>

      <View style={styles.tileHeader}>
        <Text style={styles.attackName} numberOfLines={1}>{item.name}</Text>
        <View style={[styles.severityBadge, { backgroundColor: colors.badgeBg }]}>
          <Text style={[styles.severityText, { color: colors.badgeText }]}>
            {item.severity?.toUpperCase()}
          </Text>
        </View>
      </View>

      <View style={styles.grid}>
        <View style={styles.fieldHalf}>
          <Text style={styles.fieldLabel}>IP ADDRESS</Text>
          <Text style={styles.fieldValue}>{item.ip || '—'}</Text>
        </View>
        <View style={styles.fieldHalf}>
          <Text style={styles.fieldLabel}>TIMESTAMP</Text>
          <Text style={styles.fieldValue}>{formattedTime}</Text>
        </View>
      </View>

      {item.mitre_ttps?.length > 0 && (
        <View style={styles.ttpRow}>
          <Text style={styles.fieldLabel}>MITRE TTPs</Text>
          <View style={styles.ttpTags}>
            {item.mitre_ttps.map((ttp, i) => (
              <View key={i} style={styles.ttpTag}>
                <Text style={styles.ttpText}>{ttp[0]} — {ttp[1]}</Text>
              </View>
            ))}
          </View>
        </View>
      )}
    </View>
  );
};

const DefenseScreen = ({ navigation }) => {
  const [alerts, setAlerts] = useState([]);
  const [defendedIps, setDefendedIps] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const fetchAllData = async () => {
  try {
    setLoading(true);
    setError(null);

    const [defenceRes, attacksRes] = await Promise.all([
      defenceapi.get('/defence'),
      defenceapi.get('/attacks/live'),
    ]);

    // /defence returns a flat array
    const defenceData = defenceRes.data;
    setAlerts(Array.isArray(defenceData) ? defenceData : Object.values(defenceData));

    // /attacks/live returns recent attacks
    const attacksData = attacksRes.data;
    const active = Array.isArray(attacksData.active) ? attacksData.active : [];
    const completed = Array.isArray(attacksData.completed) ? attacksData.completed : [];
    setDefendedIps([...active, ...completed]);

  } catch (err) {
    console.error("Defense API error:", err.message);
    setError(`Failed to load data. (${err.response?.status || err.message})`);
  } finally {
    setLoading(false);
  }
};

  useEffect(() => {
    fetchAllData();
  }, []);

  const sections = [
    { title: 'defended', data: defendedIps },
    { title: 'alerts', data: alerts },
  ];

  const renderItem = ({ item, section }) => {
    if (section.title === 'defended') {
      return <DefendedIpTile ip={item.ip} data={item} />;
    }
    return <DefenseTile item={item} />;
  };

  const renderSectionHeader = ({ section }) => {
    if (section.title === 'defended') {
      return (
        <View>
        </View>
      );
    }
    return (
      <View style={styles.sectionHeader}>
        <View style={[styles.sectionDot, { backgroundColor: '#5bf67c' }]} />
        <Text style={styles.sectionTitleGreen}>
          Defence Logs — {alerts.length} entr{alerts.length !== 1 ? 'ies' : 'y'}
        </Text>
      </View>
    );
  };

  if (loading) {
    return (
      <View style={[styles.container, styles.centered]}>
        <Text style={styles.emptyText}>Loading...</Text>
      </View>
    );
  }

  return (
    <View style={styles.container}>
      <View style={styles.header}>
        <Text style={styles.headerTitle}>Defense</Text>
      </View>

      {error ? (
        <View style={styles.centered}>
          <Text style={styles.emptyText}>{error}</Text>
        </View>
      ) : (
        <SectionList
          sections={sections}
          keyExtractor={(item, index) => item.session_id ?? item.id?.toString() ?? index.toString()}
          renderItem={renderItem}
          renderSectionHeader={renderSectionHeader}
          contentContainerStyle={styles.listContent}
          showsVerticalScrollIndicator={false}
          stickySectionHeadersEnabled={false}
        />
      )}

      <View style={styles.bottomNav}>
        <TouchableOpacity style={styles.navButton} onPress={() => navigation.navigate('Main')}>
          <Text style={styles.navText}>HOME</Text>
        </TouchableOpacity>
        <TouchableOpacity style={styles.navButton} onPress={() => navigation.navigate('Attacks')}>
          <Text style={styles.navText}>ATTACKS</Text>
        </TouchableOpacity>
        <TouchableOpacity style={[styles.navButton, styles.navButtonActive]}>
          <Text style={[styles.navText, styles.navTextActive]}>DEFENSE</Text>
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
  centered: { flex: 1, alignItems: "center", justifyContent: "center" },
  header: { paddingHorizontal: 16, paddingTop: 20, paddingBottom: 8 },
  headerTitle: { fontSize: 24, fontWeight: "bold", color: "#5bf67c", marginTop: 20, marginBottom: -10 },
  headerSubtitle: { fontSize: 12, color: "#8b97ad" },
  topBanner: {
    flexDirection: "row", alignItems: "center", backgroundColor: "#0a2e12",
    borderTopWidth: 0.5, borderBottomWidth: 0.5, borderColor: "#1a6e30",
    paddingHorizontal: 16, paddingVertical: 10, gap: 8,
  },
  topBannerText: { color: "#5bf67c", fontSize: 12, fontWeight: "500", flex: 1 },
  listContent: { padding: 12, paddingBottom: 80 },
  emptyText: { color: "#8b97ad", fontSize: 14 },
  sectionHeader: {
    flexDirection: "row", alignItems: "center", gap: 8,
    marginBottom: 10, marginTop: 6,
  },
  sectionDot: { width: 8, height: 8, borderRadius: 4 },
  sectionTitleGreen: { fontSize: 12, fontWeight: "600", color: "#5bf67c", letterSpacing: 0.5 },

  // Defended tile
  defendedTile: {
    borderRadius: 12, padding: 14, borderWidth: 0.5,
    marginBottom: 12, gap: 8,
    backgroundColor: '#0f2e15', borderColor: '#1a6e30',
  },
  defendedBanner: {
    flexDirection: "row", alignItems: "center",
    backgroundColor: '#5bf67c18', borderRadius: 6,
    paddingHorizontal: 10, paddingVertical: 5,
  },
  defendedBannerText: { color: '#5bf67c', fontSize: 11, fontWeight: "700", letterSpacing: 1 },
  ipBadgeGreen: { paddingHorizontal: 8, paddingVertical: 4, borderRadius: 6, backgroundColor: '#1c6e30' },
  ipTextGreen: { fontSize: 13, fontWeight: "600", color: '#5bf67c' },
  severityBadgeGreen: { paddingHorizontal: 10, paddingVertical: 3, borderRadius: 20, backgroundColor: '#5bf67c22' },
  severityTextGreen: { fontSize: 11, fontWeight: "700", letterSpacing: 0.5, color: '#5bf67c' },
  footerTextGreen: { fontSize: 11, color: '#5bf67c' },

  // Shared
  tileHeader: { flexDirection: "row", justifyContent: "space-between", alignItems: "center" },
  field: { backgroundColor: "#ffffff08", borderRadius: 6, padding: 8 },
  grid: { flexDirection: "row", gap: 8 },
  fieldHalf: { flex: 1, backgroundColor: "#ffffff08", borderRadius: 6, padding: 8 },
  fieldLabel: { fontSize: 10, color: "#8b97ad", marginBottom: 3, letterSpacing: 0.5 },
  fieldValue: { fontSize: 13, color: "#e0e6f0", fontWeight: "500" },
  fieldValueSm: { fontSize: 11, color: "#e0e6f0" },
  footer: { borderTopWidth: 0.5, borderTopColor: "#ffffff15", paddingTop: 8, marginTop: 2 },

  // Defence log tile (green)
  tile: { borderRadius: 12, padding: 14, borderWidth: 0.5, marginBottom: 12, gap: 10 },
  pulsingDot: { width: 7, height: 7, borderRadius: 4, backgroundColor: "#5bf67c" },
  attackName: { fontSize: 15, fontWeight: "600", color: "#e0e6f0", flex: 1 },
  severityBadge: { paddingHorizontal: 10, paddingVertical: 3, borderRadius: 20 },
  severityText: { fontSize: 10, fontWeight: "700", letterSpacing: 0.5 },
  ttpRow: { backgroundColor: "#ffffff08", borderRadius: 6, padding: 8, gap: 6 },
  ttpTags: { flexDirection: "row", flexWrap: "wrap", gap: 5, marginTop: 4 },
  ttpTag: { backgroundColor: '#1c6e30', paddingHorizontal: 8, paddingVertical: 3, borderRadius: 4 },
  ttpText: { fontSize: 10, color: '#5bf67c' },

  bottomNav: { flexDirection: "row", backgroundColor: "#2a3038", borderTopWidth: 1, borderTopColor: "#FF6B6B", height: 60 },
  navButton: { flex: 1, justifyContent: "center", alignItems: "center" },
  navButtonActive: { borderBottomWidth: 3, borderBottomColor: "#00BFFF" },
  navText: { color: "#999", fontSize: 12, fontWeight: "600" },
  navTextActive: { color: "#00BFFF" },
});

export default DefenseScreen;