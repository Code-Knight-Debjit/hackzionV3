import React from "react";
import { Text, StyleSheet, View, ScrollView, TouchableOpacity } from "react-native";

const DefenseScreen = ({ navigation }) => {
    const defenseLogs = [
        { time: "10:05", action: "Blocked IP: 192.168.1.1", target: "Firewall" },
        { time: "10:20", action: "Rate Limited Requests", target: "Web Server" },
        { time: "10:35", action: "Quarantined File", target: "Antivirus" },
        { time: "10:50", action: "Updated Rules", target: "IDS" },
        { time: "11:05", action: "Blocked Port 80", target: "Firewall" },
        { time: "11:20", action: "Isolated Network Segment", target: "Network Security" },
    ];

    return (
        <View style={styles.container}>
            <View style={styles.content}>
                <Text style={styles.contentTitle}>Defense Actions</Text>
                <Text style={{color:'black', marginBottom:10}}>Logs provided by the defence model, along with the solution used.</Text>
                <ScrollView>
                    {defenseLogs.map((log, index) => (
                        <View key={index} style={styles.logItem}>
                            <Text style={styles.logTime}>{log.time}</Text>
                            <View style={styles.logDetails}>
                                <Text style={styles.logText}>{log.action}</Text>
                                <Text style={styles.target}>{log.target}</Text>
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
                    style={[styles.navButton, styles.navButtonActive]}
                >
                    <Text style={[styles.navText, styles.navTextActive]}>DEFENSE</Text>
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
        backgroundColor: "#FAF9F6",
    },
    content: {
        flex: 1,
        padding: 20,
    },
    contentTitle: {
        fontSize: 28,
        fontWeight: "bold",
        color: "#4CAF50",
        marginBottom: 15,
        marginTop: 20,
    },
    logItem: {
        backgroundColor: "#E5FFE5",
        padding: 15,
        marginBottom: 10,
        borderRadius: 5,
        flexDirection: "row",
    },
    logTime: {
        fontSize: 12,
        color: "#666",
        width: 70,
    },
    logDetails: {
        flex: 1,
        marginLeft: 10,
    },
    logText: {
        fontSize: 16,
        color: "#333",
        fontWeight: "500",
    },
    target: {
        fontSize: 12,
        color: "#999",
        marginTop: 5,
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
    navTextActive: {
        color: "#00BFFF",
    },
});

export default DefenseScreen;
