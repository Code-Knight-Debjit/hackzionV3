import React from "react";
import { Text, StyleSheet, View, ScrollView, TouchableOpacity } from "react-native";

const AttacksScreen = ({ navigation }) => {
    const attackLogs = [
        { time: "10:00", attack: "Port Scan", severity: "Medium" },
        { time: "10:15", attack: "Brute Force", severity: "High" },
        { time: "10:30", attack: "DDoS Attempt", severity: "High" },
        { time: "10:45", attack: "Malware Upload", severity: "Low" },
        { time: "11:00", attack: "SQL Injection", severity: "High" },
        { time: "11:15", attack: "XSS Attack", severity: "High" },
    ];

    return (
        <View style={styles.container}>
            <View style={styles.content}>
                <Text style={styles.contentTitle}>Attack Logs</Text>
                <Text style={styles.descriptionText}>Different attacks tried by the model, along with its logs & level of attack.</Text>
                <ScrollView>
                    {attackLogs.map((log, index) => (
                        <View key={index} style={styles.logItem}>
                            <Text style={styles.logTime}>{log.time}</Text>
                            <Text style={styles.logText}>{log.attack}</Text>
                            <Text style={[styles.severity, log.severity === "High" && styles.severityHigh]}>
                                {log.severity}
                            </Text>
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
                    style={[styles.navButton, styles.navButtonActive]}
                >
                    <Text style={[styles.navText, styles.navTextActive]}>ATTACKS</Text>
                </TouchableOpacity>
                <TouchableOpacity
                    style={styles.navButton}
                    onPress={() => navigation.navigate('Defense')}
                >
                    <Text style={styles.navText}>DEFENSE</Text>
                </TouchableOpacity>
                <TouchableOpacity
                    style={styles.navButton}
                    onPress={() => navigation.navigate('Alerts')}
                >
                    <Text style={styles.navText}>ALERTS</Text>
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
        marginBottom: 15,
        marginTop: 20,
    },
    logItem: {
        backgroundColor: "#171d26",
        padding: 15,
        marginBottom: 10,
        borderRadius: 12,
        flexDirection: "row",
        justifyContent: "space-between",
        alignItems: "center",
    },
    logTime: {
        fontSize: 12,
        color: "#8b97ad",
    },
    logText: {
        fontSize: 16,
        color: "#FFFFFF",
        flex: 1,
        marginLeft: 10,
    },
    severity: {
        fontSize: 12,
        color: "#FFA500",
        fontWeight: "bold",
    },
    severityHigh: {
        color: "#FF6B6B",
    },
    bottomNav: {
        flexDirection: "row",
        backgroundColor: "#2a3038",
        borderTopWidth: 1,
        borderTopColor: "#FF6B6B",
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

export default AttacksScreen;
