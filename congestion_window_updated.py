from scapy.all import sniff, IP, TCP
import dash
import dash_core_components as dcc
import dash_html_components as html
from dash.dependencies import Input, Output
import datetime
import threading
import time

# Initialize variables for Congestion Window Tracking
timestamps = []
cwnd_values = []

# Initialize variables for packet tracking
last_ack = None
retransmissions = 0
out_of_order = 0
packet_loss = 0

# Use a lock for thread-safe access to shared variables
data_lock = threading.Lock()

# Use Queue for thread-safe communication
packet_queue = []

# Function to start packet sniffing in a separate thread
def start_sniffing():
    global last_ack, retransmissions, out_of_order, packet_loss

    while True:
        # Fetch new packets using Scapy (replace with your own logic)
        packets = sniff(prn=lambda x: packet_queue.append(x), store=0, filter="tcp", count=100)
        time.sleep(3)

# Create Dash app
app = dash.Dash(__name__)

# Define layout
app.layout = html.Div(children=[
    html.H1(children='Network Metrics Live Visualization'),

    html.Div(children='''
        Live visualization of network metrics using Dash and Scapy.
    '''),

    dcc.Graph(
        id='cwnd-plot',
        figure={
            'data': [
                {'x': timestamps, 'y': cwnd_values, 'type': 'line', 'name': 'Congestion Window Size'},
            ],
            'layout': {
                'title': 'Congestion Window Tracking',
                'xaxis': {'title': 'Time'},
                'yaxis': {'title': 'Estimated Congestion Window Size'},
            }
        }
    ),

    dcc.Graph(
        id='retransmission-plot',
        figure={
            'data': [
                {'x': [], 'y': [], 'type': 'line', 'name': 'Retransmissions'},
            ],
            'layout': {
                'title': 'Retransmissions Tracking',
                'xaxis': {'title': 'Time'},
                'yaxis': {'title': 'Count'},
            }
        }
    ),

    dcc.Graph(
        id='out-of-order-plot',
        figure={
            'data': [
                {'x': [], 'y': [], 'type': 'line', 'name': 'Out-of-Order Packets'},
            ],
            'layout': {
                'title': 'Out-of-Order Packets Tracking',
                'xaxis': {'title': 'Time'},
                'yaxis': {'title': 'Count'},
            }
        }
    ),

    dcc.Graph(
        id='packet-loss-plot',
        figure={
            'data': [
                {'x': [], 'y': [], 'type': 'line', 'name': 'Packet Loss'},
            ],
            'layout': {
                'title': 'Packet Loss Tracking',
                'xaxis': {'title': 'Time'},
                'yaxis': {'title': 'Count'},
            }
        }
    ),

    html.Div(id='metrics-text'),
    dcc.Interval(
        id='interval-component',
        interval=3*1000,  # Update every 3 seconds
        n_intervals=0
    )
])

# Callback function to update the plots and text
@app.callback(
    [Output('cwnd-plot', 'figure'),
     Output('retransmission-plot', 'figure'),
     Output('out-of-order-plot', 'figure'),
     Output('packet-loss-plot', 'figure'),
     Output('metrics-text', 'children')],
    [Input('interval-component', 'n_intervals')]
)
def update_metrics(n_intervals):
    global timestamps, cwnd_values, last_ack, retransmissions, out_of_order, packet_loss

    # Process packets from the queue
    with data_lock:
        for packet in packet_queue:
            packet_handler(packet)
        packet_queue.clear()

    # Update the plots and metrics based on the latest data
    cwnd_figure = {
        'data': [
            {'x': timestamps, 'y': cwnd_values, 'type': 'line', 'name': 'Congestion Window Size'},
        ],
        'layout': {
            'title': 'Congestion Window Tracking',
            'xaxis': {'title': 'Time'},
            'yaxis': {'title': 'Estimated Congestion Window Size'},
        }
    }

    retransmission_figure = {
        'data': [
            {'x': timestamps, 'y': [retransmissions] * len(timestamps), 'type': 'line', 'name': 'Retransmissions'},
        ],
        'layout': {
            'title': 'Retransmissions Tracking',
            'xaxis': {'title': 'Time'},
            'yaxis': {'title': 'Count'},
        }
    }

    out_of_order_figure = {
        'data': [
            {'x': timestamps, 'y': [out_of_order] * len(timestamps), 'type': 'line', 'name': 'Out-of-Order Packets'},
        ],
        'layout': {
            'title': 'Out-of-Order Packets Tracking',
            'xaxis': {'title': 'Time'},
            'yaxis': {'title': 'Count'},
        }
    }

    packet_loss_figure = {
        'data': [
            {'x': timestamps, 'y': [packet_loss] * len(timestamps), 'type': 'line', 'name': 'Packet Loss'},
        ],
        'layout': {
            'title': 'Packet Loss Tracking',
            'xaxis': {'title': 'Time'},
            'yaxis': {'title': 'Count'},
        }
    }

    metrics_text = f'Retransmissions: {retransmissions}, Out-of-Order Packets: {out_of_order}, Packet Loss: {packet_loss}'
    print(f"Retransmissions: {retransmissions}, Out-of-Order Packets: {out_of_order}, Packet Loss: {packet_loss}")
    return cwnd_figure, retransmission_figure, out_of_order_figure, packet_loss_figure, metrics_text

# Scapy packet handling logic
def packet_handler(packet):
    global timestamps, cwnd_values, last_ack, retransmissions, out_of_order, packet_loss

    if IP in packet and TCP in packet:
        # Extract TCP header information
        ack_num = packet[TCP].ack
        window_size = max(ack_num - last_ack, 0) if last_ack is not None else 0

        # Update Congestion Window Tracking
        timestamps.append(datetime.datetime.now())
        cwnd_values.append(window_size)

        # Detect retransmissions
        if last_ack is not None and ack_num < last_ack:
            retransmissions += 1

        # Detect out-of-order packets
        if last_ack is not None and ack_num != last_ack + 1:
            out_of_order += 1

        # Check for packet loss
        if packet_loss == 0 and window_size < cwnd_values[-2]:  # Assuming cwnd_values[-2] is the previous window size
            packet_loss += 1

        # Update last acknowledgment number
        last_ack = ack_num
# Start the packet sniffing thread
sniffing_thread = threading.Thread(target=start_sniffing)
sniffing_thread.daemon = True
sniffing_thread.start()

# Run the Dash app
if __name__ == '__main__':
    app.run_server(debug=True, use_reloader=False)
    print("\nAnalysis Summary:")
    print(f"Retransmissions: {retransmissions}")
    print(f"Out-of-Order Packets: {out_of_order}")
    print(f"Packet Loss: {packet_loss}")
