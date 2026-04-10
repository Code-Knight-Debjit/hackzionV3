import React from "react";
import { Text, StyleSheet, View, ScrollView, TouchableOpacity } from "react-native";

const AlertsScreen = ({ navigation }) => {
    const highVulnAttacks = [
        { name: "SQL Injection", severity: "Critical", timestamp: "10:30" },
        { name: "XSS Attack", severity: "Critical", timestamp: "10:45" },
        { name: "Buffer Overflow", severity: "Critical", timestamp: "11:00" },
    ];

    return (
        <View style={styles.container}>
            <View style={styles.content}>
                <Text style={styles.contentTitle}>High Vulnerability Alerts</Text>
                <Text style={styles.descriptionText}>List of critical attacks that were unable to be processed by the AI model.</Text>
                <ScrollView>
                    {highVulnAttacks.map((alert, index) => (
                        <View key={index} style={styles.alertItem}>
                            <View style={styles.alertIcon}>
                                <Text style={styles.iconText}>⚠️</Text>
                            </View>
                            <View style={styles.alertDetails}>
                                <Text style={styles.alertName}>{alert.name}</Text>
                                <Text style={styles.alertTimestamp}>Time: {alert.timestamp}</Text>
                                <Text style={styles.alertSeverity}>Severity: {alert.severity}</Text>
                            </View>
                        </View>
                    ))}
                </ScrollView>
            </View>

            <View style={styles.bottomNav}>
                <TouchableOpacity
                    style={styles.navButton}
                    onPress={() => navigation.navigate('Main')}
                >
                    <Text style={styles.navText}>HOME</Text>
                </TouchableOpacity>
                <TouchableOpacity
                    style={styles.navButton}
                    onPress={() => navigation.navigate('Attacks')}
                >
                    <Text style={styles.navText}>ATTACKS</Text>
                </TouchableOpacity>
                <TouchableOpacity
                    style={styles.navButton}
                    onPress={() => navigation.navigate('Defense')}
                >
                    <Text style={styles.navText}>DEFENSE</Text>
                </TouchableOpacity>
                <TouchableOpacity
                    style={[styles.navButton, styles.navButtonActive]}
                >
                    <Text style={[styles.navText, styles.navTextActive]}>ALERTS</Text>
                </TouchableOpacity>
                <TouchableOpacity style={styles.navButton} onPress={() => navigation.navigate('Profile')}>
                    <Text style={styles.navText}>PROFILE</Text>
                </TouchableOpacity>
            </View>
        </View>
    );
};

const styles = StyleSheet.create({
    container: {
        flex: 1,
        backgroundColor: "#10141a",
    },
    content: {
        flex: 1,
        padding: 20,
    },
    contentTitle: {
        fontSize: 28,
        fontWeight: "bold",
        color: "#FF6B6B",
        marginBottom: 10,
        marginTop: 20,
        fontFamily: 'Inter',
    },
    alertItem: {
        backgroundColor: "#e81515",
        padding: 15,
        marginBottom: 10,
        borderRadius: 5,
        flexDirection: "row",
        alignItems: "center",
        shadowColor: "#000",
        shadowOffset: { width: 0, height: 2 },
        shadowOpacity: 0.3,
        shadowRadius: 3,
        elevation: 5,
    },
    alertIcon: {
        marginRight: 15,
    },
    iconText: {
        fontSize: 24,
    },
    alertDetails: {
        flex: 1,
    },
    alertName: {
        fontSize: 18,
        color: "white",
        fontWeight: "bold",
    },
    alertTimestamp: {
        fontSize: 12,
        color: "#fff",
        marginTop: 5,
        opacity: 0.9,
    },
    alertSeverity: {
        fontSize: 12,
        color: "#fff",
        marginTop: 3,
        fontWeight: "bold",
        opacity: 0.9,
    },
    bottomNav: {
        flexDirection: "row",
        backgroundColor: "#2a3038",
        borderTopWidth: 1,
        borderTopColor: "#e81515",
        height: 60,
    },
    navButton: {
        flex: 1,
        justifyContent: "center",
        alignItems: "center",
    },
    navButtonActive: {
        borderBottomWidth: 3,
        borderBottomColor: "#00BFFF",
    },
    navText: {
        color: "#999",
        fontSize: 12,
        fontWeight: "600",
    },
    descriptionText: {
        color: "#A0A6B5",
        fontSize: 14,
        marginBottom: 10,
    },
    navTextActive: {
        color: "#00BFFF",
    },
});

export default AlertsScreen;
