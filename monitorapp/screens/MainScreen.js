import React from "react";
import { Text, StyleSheet, View, TouchableOpacity, ScrollView } from "react-native";
import Feather from '@expo/vector-icons/Feather';

const MainScreen = ({ navigation }) => {
    const highVulnAttacks = [
        { name: "SQL Injection", severity: "Critical", timestamp: "10:30" },
        { name: "XSS Attack", severity: "Critical", timestamp: "10:45" },
        { name: "Buffer Overflow", severity: "Critical", timestamp: "11:00" },
    ];

    const systemMetrics = [
        { label: "CPU Usage", value: "62%" },
        { label: "Memory", value: "7.4 GB" },
        { label: "Connections", value: "128" },
        { label: "Last Scan", value: "2 min ago" },
    ];

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
                            <View style={styles.statusDot} />
                            <Text style={styles.statusText}>Active</Text>
                        </View>
                        <Text style={styles.statusDetail}>Uptime: 18h 24m</Text>
                        <Text style={styles.statusDetail}>CPU threshold safe</Text>
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
                    <Text style={styles.infoText}>There are 3 critical attacks detected by the system. Review the alert log and apply firewall rules immediately. System health is stable, but keep monitoring incoming traffic patterns.</Text>
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
    container: {
        flex: 1,
        backgroundColor: '#10141a',
        paddingTop: 20
    },
    topBar: {
        flexDirection: 'row',
        justifyContent: 'space-between',
        alignItems: 'center',
        padding: 20,
    },
    title: {
        color: '#FFFFFF',
        fontSize: 24,
        fontWeight: 'bold',
    },
    subtitle: {
        color: '#A0A6B5',
        fontSize: 14,
        marginTop: 6,
    },
    logoutButton: {
        width: 44,
        height: 44,
        borderRadius: 12,
        justifyContent: 'center',
        alignItems: 'center',
    },
    scrollContent: {
        paddingHorizontal: 20,
        paddingBottom: 30,
    },
    statusRow: {
        flexDirection: 'row',
        justifyContent: 'space-between',
        marginBottom: 20,
    },
    statusCard: {
        flex: 1,
        backgroundColor: '#191d26',
        borderRadius: 18,
        padding: 20,
        marginRight: 10,
        minHeight: 150,
    },
    metricsCard: {
        marginRight: 0,
        marginLeft: 10,
        backgroundColor: '#1f2735',
    },
    cardTitle: {
        color: '#A0A6B5',
        fontSize: 13,
        textTransform: 'uppercase',
        letterSpacing: 1,
        marginBottom: 16,
    },
    statusLine: {
        flexDirection: 'row',
        alignItems: 'center',
        marginBottom: 10,
    },
    statusDot: {
        width: 10,
        height: 10,
        borderRadius: 5,
        backgroundColor: '#4CF786',
        marginRight: 10,
    },
    statusText: {
        color: '#FFFFFF',
        fontSize: 18,
        fontWeight: '700',
    },
    statusDetail: {
        color: '#8b97ad',
        fontSize: 13,
        marginBottom: 4,
    },
    alertValue: {
        color: '#FF6B6B',
        fontSize: 42,
        fontWeight: 'bold',
        marginBottom: 8,
    },
    alertLabel: {
        color: '#FFFFFF',
        fontSize: 14,
        marginBottom: 18,
    },
    viewButton: {
        alignSelf: 'flex-start',
        backgroundColor: '#0e1726',
        paddingHorizontal: 16,
        paddingVertical: 10,
        borderRadius: 12,
    },
    viewButtonText: {
        color: '#00BFFF',
        fontSize: 13,
        fontWeight: '700',
    },
    metricsGrid: {
        flexDirection: 'row',
        flexWrap: 'wrap',
        justifyContent: 'space-between',
    },
    metricCard: {
        width: '48%',
        backgroundColor: '#191d26',
        borderRadius: 18,
        padding: 18,
        marginBottom: 16,
    },
    metricValue: {
        color: '#FFFFFF',
        fontSize: 26,
        fontWeight: '700',
        marginBottom: 8,
    },
    metricLabel: {
        color: '#8b97ad',
        fontSize: 12,
    },
    infoCard: {
        backgroundColor: '#1f2735',
        borderRadius: 18,
        padding: 20,
        marginBottom: 20,
    },
    infoHeader: {
        flexDirection: 'row',
        justifyContent: 'space-between',
        alignItems: 'center',
        marginBottom: 12,
    },
    infoTitle: {
        color: '#FFFFFF',
        fontSize: 16,
        fontWeight: '700',
    },
    infoTag: {
        color: '#00BFFF',
        fontSize: 12,
        fontWeight: '700',
        letterSpacing: 1,
    },
    infoText: {
        color: '#8b97ad',
        fontSize: 14,
        lineHeight: 22,
    },
    quickActions: {
        marginBottom: 30,
    },
    sectionTitle: {
        color: '#FFFFFF',
        fontSize: 16,
        fontWeight: '700',
        marginBottom: 16,
    },
    actionRow: {
        flexDirection: 'row',
        justifyContent: 'space-between',
        marginBottom: 12,
    },
    actionRowSingle: {
        flexDirection: 'row',
        justifyContent: 'center',
        marginBottom: 12,
    },
    actionButton: {
        width: '48%',
        backgroundColor: '#191d26',
        borderRadius: 18,
        paddingVertical: 18,
        paddingHorizontal: 14,
        alignItems: 'center',
    },
    actionButtonFull: {
        width: '100%',
    },
    actionText: {
        color: '#FFFFFF',
        fontSize: 14,
        fontWeight: '700',
        marginTop: 10,
    },
});

export default MainScreen;