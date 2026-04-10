import React, { useEffect, useState } from "react";
import {
  Text, StyleSheet, View, FlatList,
  TouchableOpacity, ScrollView, Animated
} from "react-native";
import logs from "./api/logs";

const SEVERITY_LEVELS = ['Low', 'Medium', 'High', 'Critical'];

const ALIASES = [
  "Shadow Viper", "Ghost Cipher", "Iron Phantom", "Dark Nexus", "Silent Storm",
  "Neon Specter", "Void Stalker", "Binary Wraith", "Crimson Pulse", "Zero Day",
  "Null Vector", "Phantom Root", "Steel Daemon", "Echo Breach", "Apex Threat",
];

const THREAT_COLORS = {
  CRITICAL: { bg: '#0a0f1e', border: '#1e3a8a', text: '#93c5fd', badge: '#1e3a8a55' },
  HIGH:     { bg: '#0c1220', border: '#1d4ed8', text: '#60a5fa', badge: '#1d4ed855' },
  MEDIUM:   { bg: '#0d1424', border: '#2563eb', text: '#3b82f6', badge: '#2563eb55' },
  LOW:      { bg: '#0f1828', border: '#3b82f6', text: '#93c5fd', badge: '#3b82f655' },
};

// Deterministically assign alias based on IP
const getAlias = (ip) => {
  const hash = ip.split('').reduce((acc, c) => acc + c.charCodeAt(0), 0);
  return ALIASES[hash % ALIASES.length];
};

const getThreatLevel = (attackCount, severities) => {
  if (severities.includes('Critical') || attackCount >= 20) return 'CRITICAL';
  if (severities.includes('High') || attackCount >= 10) return 'HIGH';
  if (severities.includes('Medium') || attackCount >= 5) return 'MEDIUM';
  return 'LOW';
};

const PulsingDot = ({ color }) => {
  const anim = React.useRef(new Animated.Value(1)).current;
  React.useEffect(() => {
    Animated.loop(
      Animated.sequence([
        Animated.timing(anim, { toValue: 0.2, duration: 900, useNativeDriver: true }),
        Animated.timing(anim, { toValue: 1, duration: 900, useNativeDriver: true }),
      ])
    ).start();
  }, []);
  return <Animated.View style={[styles.pulsingDot, { backgroundColor: color, opacity: anim }]} />;
};

const StatBox = ({ label, value, color }) => (
  <View style={styles.statBox}>
    <Text style={[styles.statValue, { color: color || '#5b9cf6' }]}>{value}</Text>
    <Text style={styles.statLabel}>{label}</Text>
  </View>
);

const ProfileCard = ({ profile, onPress }) => {
  const colors = THREAT_COLORS[profile.threatLevel];
  return (
    <TouchableOpacity
      style={[styles.profileCard, { backgroundColor: colors.bg, borderColor: colors.border }]}
      onPress={() => onPress(profile)}
      activeOpacity={0.8}
    >
      <View style={styles.profileCardTop}>
        <View style={styles.avatarCircle}>
          <Text style={styles.avatarText}>{profile.alias.charAt(0)}</Text>
        </View>
        <View style={styles.profileCardInfo}>
          <Text style={styles.aliasText}>{profile.alias}</Text>
          <View style={styles.ipRow}>
            <Text style={styles.ipLabel}>IP  </Text>
            <Text style={styles.ipValue}>{profile.ip}</Text>
          </View>
        </View>
        <View style={[styles.threatBadge, { backgroundColor: colors.badge }]}>
          <PulsingDot color={colors.text} />
          <Text style={[styles.threatText, { color: colors.text }]}>{profile.threatLevel}</Text>
        </View>
      </View>

      <View style={styles.statsRow}>
        <StatBox label="ATTACKS" value={profile.attackCount} color={colors.text} />
        <StatBox label="ATTACK TYPES" value={profile.attackTypes.length} color={colors.text} />
        <StatBox label="LAST SEEN" value={profile.lastSeenAgo} color={colors.text} />
        <StatBox label="CVSS AVG" value={profile.avgCvss} color={colors.text} />
      </View>

      <View style={styles.tagRow}>
        {profile.attackTypes.slice(0, 3).map((t, i) => (
          <View key={i} style={[styles.tag, { borderColor: colors.border }]}>
            <Text style={[styles.tagText, { color: colors.text }]}>{t}</Text>
          </View>
        ))}
        {profile.attackTypes.length > 3 && (
          <View style={[styles.tag, { borderColor: colors.border }]}>
            <Text style={[styles.tagText, { color: colors.text }]}>+{profile.attackTypes.length - 3} more</Text>
          </View>
        )}
      </View>
    </TouchableOpacity>
  );
};

const ProfileDetail = ({ profile, onClose }) => {
  const colors = THREAT_COLORS[profile.threatLevel];
  return (
    <View style={styles.detailOverlay}>
      <ScrollView contentContainerStyle={styles.detailScroll} showsVerticalScrollIndicator={false}>

        {/* Header */}
        <View style={[styles.detailHeader, { borderColor: colors.border }]}>
          <View style={[styles.detailAvatar, { backgroundColor: colors.badge }]}>
            <Text style={[styles.detailAvatarText, { color: colors.text }]}>
              {profile.alias.charAt(0)}
            </Text>
          </View>
          <Text style={[styles.detailAlias, { color: colors.text }]}>{profile.alias}</Text>
          <Text style={styles.detailIp}>{profile.ip}</Text>
          <View style={[styles.threatBadge, { backgroundColor: colors.badge, alignSelf: 'center', marginTop: 8 }]}>
            <PulsingDot color={colors.text} />
            <Text style={[styles.threatText, { color: colors.text }]}>{profile.threatLevel} THREAT</Text>
          </View>
        </View>

        {/* Stats */}
        <View style={styles.detailStatsRow}>
          <StatBox label="TOTAL ATTACKS" value={profile.attackCount} color={colors.text} />
          <StatBox label="FIRST SEEN" value={profile.firstSeenAgo} color={colors.text} />
          <StatBox label="LAST SEEN" value={profile.lastSeenAgo} color={colors.text} />
          <StatBox label="CVSS AVG" value={profile.avgCvss} color={colors.text} />
        </View>

        {/* Behavior */}
        <View style={[styles.detailSection, { borderColor: colors.border }]}>
          <Text style={styles.detailSectionTitle}>BEHAVIOR ANALYSIS</Text>
          <View style={styles.detailGrid}>
            <View style={styles.detailField}>
              <Text style={styles.fieldLabel}>DOMINANT BEHAVIOR</Text>
              <Text style={styles.fieldValue}>{profile.dominantBehavior || '—'}</Text>
            </View>
            <View style={styles.detailField}>
              <Text style={styles.fieldLabel}>AVG CONFIDENCE</Text>
              <Text style={styles.fieldValue}>{profile.avgConfidence}%</Text>
            </View>
          </View>
        </View>

        {/* Attack Types */}
        <View style={[styles.detailSection, { borderColor: colors.border }]}>
          <Text style={styles.detailSectionTitle}>ATTACK TYPES</Text>
          <View style={styles.tagRow}>
            {profile.attackTypes.map((t, i) => (
              <View key={i} style={[styles.tag, { borderColor: colors.border }]}>
                <Text style={[styles.tagText, { color: colors.text }]}>{t}</Text>
              </View>
            ))}
          </View>
        </View>

        {/* MITRE TTPs */}
        {profile.mitreTechniques.length > 0 && (
          <View style={[styles.detailSection, { borderColor: colors.border }]}>
            <Text style={styles.detailSectionTitle}>MITRE ATT&CK TECHNIQUES</Text>
            <View style={styles.tagRow}>
              {profile.mitreTechniques.map((t, i) => (
                <View key={i} style={[styles.tag, { borderColor: colors.border }]}>
                  <Text style={[styles.tagText, { color: colors.text }]}>{t}</Text>
                </View>
              ))}
            </View>
          </View>
        )}

        {/* OWASP */}
        {profile.owaspCategories.length > 0 && (
          <View style={[styles.detailSection, { borderColor: colors.border }]}>
            <Text style={styles.detailSectionTitle}>OWASP CATEGORIES</Text>
            <View style={styles.tagRow}>
              {profile.owaspCategories.map((t, i) => (
                <View key={i} style={[styles.tag, { borderColor: colors.border }]}>
                  <Text style={[styles.tagText, { color: colors.text }]}>{t}</Text>
                </View>
              ))}
            </View>
          </View>
        )}

        {/* Recent Events */}
        <View style={[styles.detailSection, { borderColor: colors.border }]}>
          <Text style={styles.detailSectionTitle}>RECENT ATTACKS</Text>
          {profile.recentAttacks.map((atk, i) => (
            <View key={i} style={styles.recentAttackRow}>
              <View style={[styles.recentDot, { backgroundColor: colors.text }]} />
              <View style={{ flex: 1 }}>
                <Text style={styles.recentAttackType}>{atk.attack_type || '—'}</Text>
                <Text style={styles.recentAttackTime}>
                  {atk.timestamp ? new Date(atk.timestamp * 1000).toLocaleString() : '—'}
                </Text>
              </View>
              <Text style={[styles.recentCvss, { color: colors.text }]}>
                CVSS {atk.cvss_score ?? '—'}
              </Text>
            </View>
          ))}
        </View>

        <TouchableOpacity style={[styles.closeBtn, { borderColor: colors.border }]} onPress={onClose}>
          <Text style={[styles.closeBtnText, { color: colors.text }]}>CLOSE PROFILE</Text>
        </TouchableOpacity>

      </ScrollView>
    </View>
  );
};

// Build profiles from raw attack data
const buildProfiles = (attacks) => {
  const ipMap = {};

  attacks.forEach(atk => {
    const ip = atk.ip;
    if (!ip) return;
    if (!ipMap[ip]) ipMap[ip] = [];
    ipMap[ip].push(atk);
  });

  return Object.entries(ipMap)
    .filter(([, events]) => events.length >= 1)
    .map(([ip, events]) => {
      const attackTypes = [...new Set(events.map(e => e.attack_type).filter(Boolean))];
      const severities = [...new Set(events.map(e => e.severity).filter(Boolean))];
      const mitreTechniques = [...new Set(events.map(e => e.mitre_technique).filter(Boolean))];
      const owaspCategories = [...new Set(events.map(e => e.owasp_category).filter(Boolean).filter(c => c !== 'Unclassified'))];
      const behaviors = events.map(e => e.behavior).filter(Boolean);
      const behaviorCount = behaviors.reduce((acc, b) => { acc[b] = (acc[b] || 0) + 1; return acc; }, {});
      const dominantBehavior = Object.entries(behaviorCount).sort((a, b) => b[1] - a[1])[0]?.[0];

      const timestamps = events.map(e => e.timestamp).filter(Boolean);
      const firstTs = Math.min(...timestamps);
      const lastTs = Math.max(...timestamps);
      const now = Date.now() / 1000;

      const toAgo = (ts) => {
        const diff = now - ts;
        if (diff < 60) return `${Math.floor(diff)}s ago`;
        if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
        if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
        return `${Math.floor(diff / 86400)}d ago`;
      };

      const cvssScores = events.map(e => e.cvss_score).filter(n => n != null);
      const avgCvss = cvssScores.length
        ? (cvssScores.reduce((a, b) => a + b, 0) / cvssScores.length).toFixed(1)
        : '—';

      const confidences = events.map(e => e.confidence).filter(n => n != null);
      const avgConfidence = confidences.length
        ? Math.round((confidences.reduce((a, b) => a + b, 0) / confidences.length) * 100)
        : '—';

      const threatLevel = getThreatLevel(events.length, severities);

      return {
        ip,
        alias: getAlias(ip),
        attackCount: events.length,
        attackTypes,
        severities,
        mitreTechniques,
        owaspCategories,
        dominantBehavior,
        firstSeenAgo: toAgo(firstTs),
        lastSeenAgo: toAgo(lastTs),
        avgCvss,
        avgConfidence,
        threatLevel,
        recentAttacks: [...events].sort((a, b) => b.timestamp - a.timestamp).slice(0, 5),
      };
    })
    .sort((a, b) => {
      const order = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
      return order[a.threatLevel] - order[b.threatLevel];
    });
};

const AttackerProfileScreen = ({ navigation }) => {
  const [profiles, setProfiles] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [selectedProfile, setSelectedProfile] = useState(null);

  const fetchProfiles = async () => {
    try {
      setLoading(true);
      setError(null);

      const results = await Promise.all(
        SEVERITY_LEVELS.map(sev => logs.get('/attacks', { params: { severity: sev } }))
      );

      const allAttacks = results.flatMap(res => {
        const data = res.data;
        return Array.isArray(data) ? data
          : Array.isArray(data.attacks) ? data.attacks
          : [];
      });

      setProfiles(buildProfiles(allAttacks));
    } catch (err) {
      console.error("Profile fetch error:", err.message);
      setError("Failed to load attacker profiles.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { fetchProfiles(); }, []);

  const criticalCount = profiles.filter(p => p.threatLevel === 'CRITICAL').length;
  const highCount = profiles.filter(p => p.threatLevel === 'HIGH').length;

  if (selectedProfile) {
    return <ProfileDetail profile={selectedProfile} onClose={() => setSelectedProfile(null)} />;
  }

  return (
    <View style={styles.container}>

      <View style={styles.header}>
        <Text style={styles.headerTitle}>Attacker Profiles</Text>
        <Text style={styles.headerSubtitle}>
          {profiles.length} profiled · {criticalCount} critical · {highCount} high
        </Text>
      </View>

      <FlatList
        data={profiles}
        keyExtractor={(item) => item.ip}
        renderItem={({ item }) => (
          <ProfileCard profile={item} onPress={setSelectedProfile} />
        )}
        contentContainerStyle={styles.listContent}
        showsVerticalScrollIndicator={false}
        ListEmptyComponent={
          <View style={styles.emptyContainer}>
            <Text style={styles.emptyText}>
              {error ? error : loading ? "Building profiles..." : "No profiles found."}
            </Text>
          </View>
        }
      />

      <View style={styles.bottomNav}>
        <TouchableOpacity style={styles.navButton} onPress={() => navigation.navigate('Main')}>
          <Text style={styles.navText}>HOME</Text>
        </TouchableOpacity>
        <TouchableOpacity style={styles.navButton} onPress={() => navigation.navigate('Attacks')}>
          <Text style={styles.navText}>ATTACKS</Text>
        </TouchableOpacity>
        <TouchableOpacity style={styles.navButton} onPress={() => navigation.navigate('Defense')}>
          <Text style={styles.navText}>DEFENSE</Text>
        </TouchableOpacity>
        <TouchableOpacity style={[styles.navButton, styles.navButtonActive]}>
          <Text style={[styles.navText, styles.navTextActive]}>PROFILES</Text>
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
  listContent: { padding: 12, paddingBottom: 80 },
  emptyContainer: { alignItems: "center", justifyContent: "center", paddingTop: 60 },
  emptyText: { color: "#8b97ad", fontSize: 14 },

  // Profile Card
  profileCard: { borderRadius: 14, padding: 14, borderWidth: 0.5, marginBottom: 12, gap: 12 },
  profileCardTop: { flexDirection: 'row', alignItems: 'center', gap: 12 },
  avatarCircle: {
    width: 44, height: 44, borderRadius: 22,
    backgroundColor: '#1c3a6e', alignItems: 'center', justifyContent: 'center',
  },
  avatarText: { fontSize: 18, fontWeight: 'bold', color: '#5b9cf6' },
  profileCardInfo: { flex: 1 },
  aliasText: { fontSize: 15, fontWeight: '700', color: '#e0e6f0', marginBottom: 3 },
  ipRow: { flexDirection: 'row', alignItems: 'center' },
  ipLabel: { fontSize: 10, color: '#8b97ad', letterSpacing: 0.5 },
  ipValue: { fontSize: 11, color: '#5b9cf6', fontWeight: '600' },
  threatBadge: { flexDirection: 'row', alignItems: 'center', gap: 5, paddingHorizontal: 10, paddingVertical: 4, borderRadius: 20 },
  threatText: { fontSize: 10, fontWeight: '700', letterSpacing: 0.5 },
  pulsingDot: { width: 6, height: 6, borderRadius: 3 },

  statsRow: { flexDirection: 'row', justifyContent: 'space-between' },
  statBox: { flex: 1, alignItems: 'center', backgroundColor: '#0d1f3c', borderRadius: 8, padding: 8 },
  statValue: { fontSize: 16, fontWeight: 'bold' },
  statLabel: { fontSize: 9, color: '#8b97ad', marginTop: 2, letterSpacing: 0.3 },

  tagRow: { flexDirection: 'row', flexWrap: 'wrap', gap: 6 },
  tag: { borderRadius: 6, paddingHorizontal: 8, paddingVertical: 3, borderWidth: 0.5, backgroundColor: '#0d1f3c' },
  tagText: { fontSize: 10 },

  // Detail Overlay
  detailOverlay: { flex: 1, backgroundColor: '#10141a' },
  detailScroll: { padding: 16, paddingBottom: 40 },
  detailHeader: { alignItems: 'center', borderBottomWidth: 0.5, paddingBottom: 20, marginBottom: 16 },
  detailAvatar: { width: 72, height: 72, borderRadius: 36, alignItems: 'center', justifyContent: 'center', marginBottom: 12 },
  detailAvatarText: { fontSize: 30, fontWeight: 'bold' },
  detailAlias: { fontSize: 22, fontWeight: 'bold', marginBottom: 4 },
  detailIp: { fontSize: 13, color: '#8b97ad' },
  detailStatsRow: { flexDirection: 'row', gap: 8, marginBottom: 16 },
  detailSection: { borderWidth: 0.5, borderRadius: 12, padding: 12, marginBottom: 12, gap: 10 },
  detailSectionTitle: { fontSize: 11, color: '#8b97ad', fontWeight: '700', letterSpacing: 0.8, marginBottom: 4 },
  detailGrid: { flexDirection: 'row', gap: 8 },
  detailField: { flex: 1, backgroundColor: '#0d1f3c', borderRadius: 8, padding: 8 },

  fieldLabel: { fontSize: 10, color: "#8b97ad", marginBottom: 3, letterSpacing: 0.5 },
  fieldValue: { fontSize: 13, color: "#e0e6f0", fontWeight: "500" },

  recentAttackRow: { flexDirection: 'row', alignItems: 'center', gap: 10, paddingVertical: 6, borderBottomWidth: 0.5, borderBottomColor: '#ffffff10' },
  recentDot: { width: 6, height: 6, borderRadius: 3 },
  recentAttackType: { fontSize: 12, color: '#e0e6f0', fontWeight: '500' },
  recentAttackTime: { fontSize: 10, color: '#8b97ad', marginTop: 2 },
  recentCvss: { fontSize: 11, fontWeight: '600' },

  closeBtn: { borderWidth: 1, borderRadius: 10, padding: 14, alignItems: 'center', marginTop: 8 },
  closeBtnText: { fontSize: 13, fontWeight: '700', letterSpacing: 0.5 },

  bottomNav: { flexDirection: "row", backgroundColor: "#2a3038", borderTopWidth: 1, borderTopColor: "#FF6B6B", height: 60 },
  navButton: { flex: 1, justifyContent: "center", alignItems: "center" },
  navButtonActive: { borderBottomWidth: 3, borderBottomColor: "#00BFFF" },
  navText: { color: "#999", fontSize: 12, fontWeight: "600" },
  navTextActive: { color: "#00BFFF" },
});

export default AttackerProfileScreen;