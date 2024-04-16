#! /usr/bin/env python3

import sys
from scapy.all import IP, TCP, UDP, sniff
import time
import pandas as pd
import threading
from threading import Lock
import pickle
from scipy.stats import entropy
# import all the metrics we'll use later on
from sklearn.preprocessing import StandardScaler
from sklearn.cluster import KMeans
from sklearn.metrics import (
    pairwise_distances,
    accuracy_score
)

# Global data
processing_interval = 1  # Time interval for processing data in seconds

# Define a threshold for abnormal packet size (adjust based on your network)
abnormal_size_threshold = 1500  # threshold in bytes

# Define a threshold for port frequency
port_frequency_threshold = 5

# Define a short-lived connection, e.g., less than 5 packets
short_lived_threshold = 5

new_df = pd.DataFrame()  # DataFrame for ongoing data collection

new_df_lock = Lock()

scaler = None
threshold = None
cluster_centroids = None
source_mapping = None
destination_mapping = None

def receive_pkt(pkt):
    global new_df, source_mapping, destination_mapping # Ensure that we're using the global variables

    # Check if the packet is either TCP or UDP
    if pkt.haslayer(TCP) or pkt.haslayer(UDP):
        timestamp = pkt.time

        if pkt.haslayer(IP):
            ip_layer = pkt[IP]

            ip_src = ip_layer.src
            ip_dst = ip_layer.dst
            protocol = ip_layer.proto
            # total_length = ip_layer.len
            ttl = ip_layer.ttl
            packet_size = len(pkt)

            # Initialize default values
            # Initialize as 0
            ack_flag = syn_flag = fin_flag = psh_flag = urg_flag = rst_flag = 0
            src_port = dst_port = sequence = acknowledgment = 0
            udp_flag = tcp_flag = 0
            payload_size = 0

            if pkt.haslayer(TCP):
                tcp_layer = pkt[TCP]
                ack_flag = int(tcp_layer.flags.A)
                syn_flag = int(tcp_layer.flags.S)
                fin_flag = int(tcp_layer.flags.F)
                psh_flag = int(tcp_layer.flags.P)
                urg_flag = int(tcp_layer.flags.U)
                rst_flag = int(tcp_layer.flags.R)
                src_port = tcp_layer.sport
                dst_port = tcp_layer.dport
                sequence = tcp_layer.seq
                acknowledgment = tcp_layer.ack
                tcp_flag = 1
                payload_size = len(tcp_layer.payload)

            elif pkt.haslayer(UDP):
                udp_layer = pkt[UDP]
                src_port = udp_layer.sport
                dst_port = udp_layer.dport
                udp_flag = 1
                payload_size = len(udp_layer.payload)

            # Set Label to 1 if src_port or dst_port is 9, otherwise set to 0
            label = 1 if src_port == 9 or dst_port == 9 else 0

            # Prepare data for a single packet
            packet_data = {
                'Timestamp': timestamp,
                'Source': ip_src,
                'Destination': ip_dst,
                'Protocol': protocol,
                'SrcPort': src_port,
                'DstPort': dst_port,
                'TCP': tcp_flag,
                'UDP': udp_flag,
                'TTL': ttl,
                'ACK': ack_flag,
                'SYN': syn_flag,
                'FIN': fin_flag,
                'PSH': psh_flag,
                'URG': urg_flag,
                'RST': rst_flag,
                'SequenceNumber': sequence,
                'AcknowledgmentNumber': acknowledgment,
                'PacketSize': packet_size,
                'PayloadSize': payload_size,
                'Label': label
            }

            # Create a temporary DataFrame for the single packet
            tmp_df = pd.DataFrame([packet_data])

            # Append new data to the existing DataFrame
            new_df = pd.concat([new_df, tmp_df], ignore_index=True)

def process_data_periodically():
    global new_df
    old_df = pd.DataFrame()  # DataFrame for processing

    while True:
        time.sleep(processing_interval)  # Wait for the specified number of seconds

        if new_df is None or new_df.empty:
            continue

        with new_df_lock:
            # Append new data to the existing DataFrame
            old_df = new_df.copy()
            new_df =  new_df = pd.DataFrame() # clear to start new stats

        # Ensure 'Timestamp' is in a proper datetime format if it's not already
        old_df['Timestamp'] = pd.to_datetime(old_df['Timestamp'], unit='s')

        # Calculate the time difference between each packet and the next
        # Sort the DataFrame by Timestamp first to ensure the order is correct
        old_df = old_df.sort_values(by='Timestamp')

        # Calculate the time difference in seconds between consecutive rows
        old_df['TimeDiff'] = old_df['Timestamp'].diff().dt.total_seconds().fillna(0)

        # print (old_df)

        # Feature calculation functions

        # calculate the most frequent destination port
        def calculate_destination_port_entropy(group):
            port_counts = group['DstPort'].value_counts()
            probabilities = port_counts / port_counts.sum()
            return entropy(probabilities)

        # calculate the most frequent source port
        def most_frequent_src_port(group):
            if group['SrcPort'].value_counts().max() > port_frequency_threshold:  # Threshold condition
                return group['SrcPort'].value_counts().idxmax()
            else:
                return 0

        # calculate the most frequent destination port
        def most_frequent_dst_port(group):
            if group['DstPort'].value_counts().max() > port_frequency_threshold:  # Threshold condition
                return group['DstPort'].value_counts().idxmax()
            else:
                return 0

        def calculate_short_lived_connections(group):
            # Use the 'size' attribute correctly
            return (group['PacketSize'].count() < short_lived_threshold).sum()

        def repeated_connection_attempts(group):
            return group['Destination'].duplicated().sum()

        def network_scanning_activity(group):
            # Assuming SYN flag is 1 for scan attempts and ACK is 0
            return ((group['SYN'] == 1) & (group['ACK'] == 0)).sum()

        # Calculate the flow rate as packets per second in each window (for each group)
        def calculate_flow_rate(group):
            total_time = group['TimeDiff'].sum()
            packet_count = len(group)
            if total_time > 0:
                return packet_count / total_time
            else:
                return packet_count

        def calculate_entropy(group):
            return entropy(group['Source'].value_counts())

        def connection_errors(group):
            # Assuming RST flag indicates connection errors
            return (group['RST'] == 1).sum()

        # Function to calculate the frequency of the most frequent packet size
        def most_frequent_packet_size_freq(x):
            return x['PacketSize'].value_counts().max()

        # Function to calculate the frequency of abnormal packet sizes
        def abnormal_size_freq(x):
            return (x['PacketSize'] > abnormal_size_threshold).sum()

        # Function to calculate the variance in sequence numbers
        def sequence_number_variance(x):
            return x['SequenceNumber'].var()

        def calculate_avg_packet_number(group):
            return len(group['Source']) / processing_interval

        def calculate_syn_frequency(group):
            # Count the number of packets with SYN flag set
            syn_count = group[group['SYN'] == 1].shape[0]
            # Calculate the frequency by dividing the count by the processing interval
            return syn_count / processing_interval

        def calculate_ack_frequency(group):
            # Count the number of packets with ACK flag set
            ack_count = group[group['ACK'] == 1].shape[0]
            # Calculate the frequency by dividing the count by the processing interval
            return ack_count / processing_interval

        def calculate_tcp_frequency(group):
            tcp_count = group[group['TCP'] == 1].shape[0]
            total_count = len(group)
            if total_count > 0:
                return tcp_count / total_count
            else:
                return 0

        def calculate_udp_frequency(group):
            udp_count = group[group['UDP'] == 1].shape[0]
            total_count = len(group)
            if total_count > 0:
                return udp_count / total_count
            else:
                return 0

        def most_frequent_protocol(group):
            if not group.empty:
                freq_protocol = group['Protocol'].value_counts().idxmax()
                return freq_protocol
            else:
                return 0

        def packet_size_variability(group):
            return group['PacketSize'].var()  # Variance of packet sizes

        # Calculating the most frequent payload sizes
        def most_frequent_payload_size(group):
            return group['PayloadSize'].value_counts().idxmax()

        # Calculating the average payload sizes
        def average_payload_size(group):
            return group['PayloadSize'].mean()

        # Group by 'key' to calculate statistical features
        old_df['key'] = 1

        grouped = old_df.groupby('key')

        # Calculate statistical features for each window
        dst_port_entropy = grouped.apply(calculate_destination_port_entropy).reset_index(name='DstPortEntropy')
        packet_counts = grouped.size().reset_index(name='PacketCount')
        most_freq_src_port = grouped.apply(most_frequent_src_port).reset_index(name='MostFreqSrcPort')
        most_freq_dst_port = grouped.apply(most_frequent_dst_port).reset_index(name='MostFreqDstPort')
        packetsize_std = grouped['PacketSize'].std().reset_index(name='PacketSizeStd')
        avg_packet_size = grouped['PacketSize'].mean().reset_index(name='AvgPacketSize')
        most_freq_packet_size = grouped.apply(most_frequent_packet_size_freq).reset_index(name='MostFreqPacketizeFreq')
        abnormal_size_frequency = grouped.apply(abnormal_size_freq).reset_index(name='AbnormalSizeFreq')
        seq_num_variance = grouped.apply(sequence_number_variance).reset_index(name='SeqNumVariance')
        short_lived_connections = grouped.apply(calculate_short_lived_connections).reset_index(name='ShortLivedConnections')
        repeated_attempts = grouped.apply(repeated_connection_attempts).reset_index(name='RepeatedAttempts')
        scanning_activity = grouped.apply(network_scanning_activity).reset_index(name='ScanningActivity')
        flow_rate = grouped.apply(calculate_flow_rate).reset_index(name='FlowRate')
        source_entropy = grouped.apply(calculate_entropy).reset_index(name='SourceEntropy')
        connection_errors = grouped.apply(connection_errors).reset_index(name='ConnectionErrors')
        avg_packet_number = grouped.apply(calculate_avg_packet_number).reset_index(name='AvgPacketNumber')
        syn_frequency = grouped.apply(calculate_syn_frequency).reset_index(name='SYNFrequency')
        ack_frequency = grouped.apply(calculate_ack_frequency).reset_index(name='ACKFrequency')
        tcp_frequency = grouped.apply(calculate_tcp_frequency).reset_index(name='TCPFrequency')
        udp_frequency = grouped.apply(calculate_udp_frequency).reset_index(name='UDPFrequency')
        most_freq_protocol = grouped.apply(most_frequent_protocol).reset_index(name='MostFreqProtocol')
        packet_size_var = grouped.apply(packet_size_variability).reset_index(name='PacketSizeVar')
        most_freq_payload_size = grouped.apply(most_frequent_payload_size).reset_index(name='MostFreqPayloadSize')
        avg_payload_size = grouped.apply(average_payload_size).reset_index(name='AvgPayloadSize')

        # Merge the features into a single DataFrame
        # Merge each DataFrame with features_df on 'Source'
        # Start with the first DataFrame as the base
        features_df = packetsize_std

        # List of other DataFrames to merge
        other_dfs = [packet_counts, most_freq_src_port, most_freq_dst_port, avg_packet_size, most_freq_packet_size,
        abnormal_size_frequency, seq_num_variance, short_lived_connections, repeated_attempts, scanning_activity,
        flow_rate, source_entropy, connection_errors, dst_port_entropy, avg_packet_number, syn_frequency, ack_frequency,
        tcp_frequency, udp_frequency, most_freq_protocol, packet_size_var, most_freq_payload_size, avg_payload_size]

        for df in other_dfs:
            features_df = pd.merge(features_df, df, on='key', how='left')

        # Filling NaN values if any
        features_df.fillna(0, inplace=True)

        # We create a temporary key for this dataframes to merge on with the original dataframe
        features_df['key'] = 1

        # Perform the cross join
        merged_df = pd.merge(old_df, features_df, on='key')

        # Drop the temporary key column
        merged_df = merged_df.drop('key', axis=1)

        # Filling NaN values if any
        merged_df.fillna(0, inplace=True)

        # Remove some columns now that we don't need them
        merged_df = merged_df.drop(columns=['Timestamp', 'TimeDiff', 'Source','Destination', 'SrcPort', 'DstPort'])

        # Split data into features and target
        X = merged_df.drop('Label', axis=1)
        y = merged_df['Label']

        # dropping non-statistical feature
        # merged_df = merged_df.drop(columns=['Source','Destination','ACK','SYN','FIN','PSH','URG','RST','TTL','TotalLength','SequenceNumber','AcknowledgmentNumber'])

        if not merged_df.empty:
            # Standardize data only if there is data to process
            X_scaled = scaler.transform(X) # we are not using the labeling in the prediction

            # Calculate the distances to centroids for each instance
            distances = pairwise_distances(X_scaled, cluster_centroids, metric='euclidean')

            # Calculate the minimum distance for each instance
            min_distances = distances.min(axis=1)

            # Classify as malicious (1) or benign (0) based on the threshold

            predicted_labels = (min_distances > threshold).astype(int)
            accuracy = accuracy_score(y, predicted_labels)
            # precision = precision_score(y, predicted_labels)
            # recall = recall_score(y, predicted_labels)
            # f1score = f1_score(y, predicted_labels)

            # Assuming min_distances and threshold are already defined
            above_threshold_count = (min_distances > threshold).sum()

            #print(f"Number of distances above threshold: {above_threshold_count} out of {len(min_distances)}, Accuracy = {accuracy.round(4)}, Precision = {precision.round(4)}, Recall = {recall.round(4)}, F1 Score = {f1score.round(4)}")
            print(f"Number of distances above threshold: {above_threshold_count} out of {len(min_distances)}, Accuracy = {accuracy.round(4)}")

            # Classify each instance
            # cnt = 0
            # for min_distance in min_distances:
            #     if min_distance > threshold:
            #         print(f"Malicious traffic detected")
            #         print(len(merged_df), merged_df.loc[[cnt]])
            #     cnt = cnt + 1
                    # classPrediction.append(1)  # Malicious traffic
                #else:
                #    classPrediction.append(0)  # Benign traffic

def packet_sniffer(interface):
    while True:
        sniff(iface=interface, prn=receive_pkt, store=0)

def main():
    global scaler, threshold, cluster_centroids, source_mapping, destination_mapping

    interface = 'eth0'

    try:
        with open("kmeans_model.pkl", "rb") as f:
            model = pickle.load(f)
        threshold = model["threshold"]
        scaler = model["scaler"]
        cluster_centroids = model["cluster_centroids"]

    except FileNotFoundError:
        print("Model file not found.")
        sys.exit(1)
    except Exception as e:
        print(f"Error loading model: {e}")
        sys.exit(1)

    print("\n**************** Threshold is: ", threshold," *****************\n")

    # Start packet sniffer in a separate thread
    sniffer_thread = threading.Thread(target=packet_sniffer, args=(interface,))
    sniffer_thread.daemon = True
    sniffer_thread.start()

    # Start data processing in a separate thread
    data_processor_thread = threading.Thread(target=process_data_periodically)
    data_processor_thread.daemon = True
    data_processor_thread.start()

    try:
        while True:
            time.sleep(1)  # Keep the main thread alive
    except KeyboardInterrupt:
        print("Sniffing and data processing stopped.")

if __name__ == "__main__":
    main()