#!/usr/bin/env python3
"""
NetTrafficAnalyzer Web Interface
Modern web application for analyzing network traffic with interactive visualizations
"""

import os
import json
import tempfile
from datetime import datetime
from typing import Dict, Any

import dash
from dash import dcc, html, Input, Output, State, dash_table
import dash_bootstrap_components as dbc
import plotly.express as px
import plotly.graph_objects as go
import pandas as pd
from flask import Flask, request, jsonify, send_file
from werkzeug.utils import secure_filename

from analyzer import NetworkTrafficAnalyzer


# Initialize Flask app
server = Flask(__name__)
server.config['UPLOAD_FOLDER'] = 'uploads'
server.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100MB max file size

# Ensure upload directory exists
os.makedirs(server.config['UPLOAD_FOLDER'], exist_ok=True)

# Initialize Dash app
app = dash.Dash(__name__, server=server, external_stylesheets=[dbc.themes.BOOTSTRAP])
app.title = "NetTrafficAnalyzer - Network Security Dashboard"

# Global variables to store analysis results
current_analysis = None
current_analyzer = None

# Define app layout
app.layout = dbc.Container([
    dbc.Row([
        dbc.Col([
            html.H1("🔒 NetTrafficAnalyzer", className="text-center mb-4"),
            html.P("Advanced Network Traffic Analysis & Security Monitoring", 
                   className="text-center text-muted mb-5")
        ])
    ]),
    
    # Upload Section
    dbc.Row([
        dbc.Col([
            dbc.Card([
                dbc.CardHeader(html.H4("📁 Upload PCAP File")),
                dbc.CardBody([
                    dcc.Upload(
                        id='upload-pcap',
                        children=html.Div([
                            'Drag and Drop or ',
                            html.A('Select PCAP File')
                        ]),
                        style={
                            'width': '100%',
                            'height': '60px',
                            'lineHeight': '60px',
                            'borderWidth': '1px',
                            'borderStyle': 'dashed',
                            'borderRadius': '5px',
                            'textAlign': 'center',
                            'margin': '10px'
                        },
                        multiple=False
                    ),
                    html.Div(id='upload-status'),
                    dbc.Button("Analyze Traffic", id="analyze-btn", color="primary", 
                              disabled=True, className="mt-3"),
                ])
            ])
        ], width=12)
    ], className="mb-4"),
    
    # Analysis Progress
    dbc.Row([
        dbc.Col([
            dbc.Progress(id="progress-bar", value=0, style={"display": "none"}),
            html.Div(id="analysis-status", className="mt-2")
        ])
    ], className="mb-4"),
    
    # Summary Cards
    dbc.Row([
        dbc.Col([
            dbc.Card([
                dbc.CardBody([
                    html.H4("0", id="total-packets", className="text-primary"),
                    html.P("Total Packets", className="card-text")
                ])
            ])
        ], width=3),
        dbc.Col([
            dbc.Card([
                dbc.CardBody([
                    html.H4("0", id="anomalies-count", className="text-danger"),
                    html.P("Anomalies Detected", className="card-text")
                ])
            ])
        ], width=3),
        dbc.Col([
            dbc.Card([
                dbc.CardBody([
                    html.H4("0", id="dns-queries", className="text-info"),
                    html.P("DNS Queries", className="card-text")
                ])
            ])
        ], width=3),
        dbc.Col([
            dbc.Card([
                dbc.CardBody([
                    html.H4("0", id="http-requests", className="text-success"),
                    html.P("HTTP Requests", className="card-text")
                ])
            ])
        ], width=3)
    ], className="mb-4"),
    
    # Tabs for different views
    dbc.Tabs([
        dbc.Tab(label="📊 Overview", tab_id="overview"),
        dbc.Tab(label="🚨 Anomalies", tab_id="anomalies"),
        dbc.Tab(label="📡 Protocols", tab_id="protocols"),
        dbc.Tab(label="🌐 Network Analysis", tab_id="network"),
        dbc.Tab(label="📈 Time Analysis", tab_id="timeline")
    ], id="tabs", active_tab="overview"),
    
    # Tab content
    html.Div(id="tab-content", className="mt-4"),
    
    # Hidden div to store data
    html.Div(id="analysis-data", style={"display": "none"}),
    
], fluid=True)


# Callback for file upload
@app.callback(
    [Output('upload-status', 'children'),
     Output('analyze-btn', 'disabled')],
    Input('upload-pcap', 'contents'),
    State('upload-pcap', 'filename')
)
def handle_upload(contents, filename):
    if contents is not None:
        # Save uploaded file
        content_type, content_string = contents.split(',')
        decoded = base64.b64decode(content_string)
        
        # Ensure filename is safe
        if filename and filename.endswith('.pcap'):
            filepath = os.path.join(server.config['UPLOAD_FOLDER'], secure_filename(filename))
            with open(filepath, 'wb') as f:
                f.write(decoded)
            
            return [
                dbc.Alert(f"✅ File '{filename}' uploaded successfully!", color="success"),
                False
            ]
        else:
            return [
                dbc.Alert("❌ Please upload a valid PCAP file (.pcap extension)", color="danger"),
                True
            ]
    
    return ["", True]


# Callback for analysis
@app.callback(
    [Output('analysis-data', 'children'),
     Output('analysis-status', 'children'),
     Output('progress-bar', 'style'),
     Output('total-packets', 'children'),
     Output('anomalies-count', 'children'),
     Output('dns-queries', 'children'),
     Output('http-requests', 'children')],
    Input('analyze-btn', 'n_clicks'),
    State('upload-pcap', 'filename')
)
def analyze_traffic(n_clicks, filename):
    if n_clicks is None or filename is None:
        return "", "", {"display": "none"}, "0", "0", "0", "0"
    
    try:
        # Show progress
        filepath = os.path.join(server.config['UPLOAD_FOLDER'], secure_filename(filename))
        
        # Initialize analyzer
        global current_analyzer, current_analysis
        current_analyzer = NetworkTrafficAnalyzer()
        
        # Load and analyze PCAP
        if current_analyzer.load_pcap(filepath):
            current_analysis = current_analyzer.run_full_analysis()
            
            summary = current_analysis['summary']
            
            return [
                json.dumps(current_analysis, default=str),
                dbc.Alert("✅ Analysis completed successfully!", color="success"),
                {"display": "none"},
                str(summary['total_packets']),
                str(summary['total_anomalies']),
                str(summary['dns_queries']),
                str(summary['http_requests'])
            ]
        else:
            return [
                "",
                dbc.Alert("❌ Failed to analyze PCAP file", color="danger"),
                {"display": "none"},
                "0", "0", "0", "0"
            ]
    
    except Exception as e:
        return [
            "",
            dbc.Alert(f"❌ Error during analysis: {str(e)}", color="danger"),
            {"display": "none"},
            "0", "0", "0", "0"
        ]


# Callback for tab content
@app.callback(
    Output('tab-content', 'children'),
    [Input('tabs', 'active_tab'),
     Input('analysis-data', 'children')]
)
def update_tab_content(active_tab, analysis_data):
    if analysis_data is None or analysis_data == "":
        return html.Div([
            dbc.Alert("📋 Please upload and analyze a PCAP file to view results", 
                     color="info", className="text-center")
        ])
    
    try:
        data = json.loads(analysis_data)
        
        if active_tab == "overview":
            return create_overview_tab(data)
        elif active_tab == "anomalies":
            return create_anomalies_tab(data)
        elif active_tab == "protocols":
            return create_protocols_tab(data)
        elif active_tab == "network":
            return create_network_tab(data)
        elif active_tab == "timeline":
            return create_timeline_tab(data)
    
    except Exception as e:
        return dbc.Alert(f"Error displaying results: {str(e)}", color="danger")
    
    return html.Div()


def create_overview_tab(data):
    """Create overview tab with summary charts"""
    summary = data['summary']
    
    # Protocol distribution pie chart
    protocol_fig = px.pie(
        values=list(summary['protocol_distribution'].values()),
        names=list(summary['protocol_distribution'].keys()),
        title="Protocol Distribution"
    )
    
    # Top ports bar chart
    top_ports = summary.get('top_ports', {})
    if top_ports:
        ports_fig = px.bar(
            x=list(top_ports.keys()),
            y=list(top_ports.values()),
            title="Top Active Ports",
            labels={'x': 'Port', 'y': 'Connections'}
        )
    else:
        ports_fig = go.Figure()
        ports_fig.add_annotation(text="No port data available", 
                               xref="paper", yref="paper",
                               x=0.5, y=0.5, showarrow=False)
    
    return dbc.Row([
        dbc.Col([
            dcc.Graph(figure=protocol_fig)
        ], width=6),
        dbc.Col([
            dcc.Graph(figure=ports_fig)
        ], width=6)
    ])


def create_anomalies_tab(data):
    """Create anomalies tab with detailed anomaly information"""
    anomalies = data['detailed_results']['anomalies']
    
    if not anomalies:
        return dbc.Alert("✅ No anomalies detected in the traffic!", color="success")
    
    # Convert anomalies to DataFrame for table
    df = pd.DataFrame(anomalies)
    df['timestamp'] = pd.to_datetime(df['timestamp'], unit='s')
    df['timestamp'] = df['timestamp'].dt.strftime('%Y-%m-%d %H:%M:%S')
    
    # Anomaly type distribution
    anomaly_counts = df['type'].value_counts()
    anomaly_fig = px.bar(
        x=anomaly_counts.values,
        y=anomaly_counts.index,
        orientation='h',
        title="Anomaly Types Distribution"
    )
    
    return dbc.Row([
        dbc.Col([
            dcc.Graph(figure=anomaly_fig)
        ], width=6),
        dbc.Col([
            html.H5("Anomaly Details"),
            dash_table.DataTable(
                data=df.to_dict('records'),
                columns=[
                    {"name": "Type", "id": "type"},
                    {"name": "Description", "id": "description"},
                    {"name": "Timestamp", "id": "timestamp"},
                    {"name": "Source IP", "id": "src_ip"}
                ],
                style_cell={'textAlign': 'left'},
                style_data_conditional=[
                    {
                        'if': {'filter_query': '{type} contains "Suspicious"'},
                        'backgroundColor': '#ffebee',
                        'color': 'black',
                    }
                ],
                page_size=10,
                sort_action="native"
            )
        ], width=6)
    ])


def create_protocols_tab(data):
    """Create protocols analysis tab"""
    protocols = data['summary']['protocol_distribution']
    
    # Protocol timeline (if packet data available)
    protocol_fig = px.pie(
        values=list(protocols.values()),
        names=list(protocols.keys()),
        title="Network Protocol Distribution",
        hole=0.3
    )
    
    return dbc.Row([
        dbc.Col([
            dcc.Graph(figure=protocol_fig)
        ], width=8),
        dbc.Col([
            html.H5("Protocol Summary"),
            html.Div([
                dbc.ListGroup([
                    dbc.ListGroupItem([
                        html.Div([
                            html.H6(f"{protocol}", className="mb-1"),
                            html.P(f"{count} packets ({count/sum(protocols.values())*100:.1f}%)", 
                                   className="mb-1 text-muted")
                        ])
                    ]) for protocol, count in protocols.items()
                ])
            ])
        ], width=4)
    ])


def create_network_tab(data):
    """Create network analysis tab"""
    conversations = data['detailed_results'].get('ip_conversations', {})
    
    if not conversations:
        return dbc.Alert("No IP conversation data available", color="info")
    
    # Convert conversations to DataFrame
    conv_data = []
    for conv, count in list(conversations.items())[:20]:  # Top 20
        src, dst = conv.split(' -> ')
        conv_data.append({'source': src, 'destination': dst, 'packets': count})
    
    conv_df = pd.DataFrame(conv_data)
    
    # Network graph would be complex, so show top conversations
    conv_fig = px.bar(
        conv_df.head(10),
        x='packets',
        y=[f"{row['source']} → {row['destination']}" for _, row in conv_df.head(10).iterrows()],
        orientation='h',
        title="Top IP Conversations"
    )
    
    return dbc.Row([
        dbc.Col([
            dcc.Graph(figure=conv_fig)
        ], width=12)
    ])


def create_timeline_tab(data):
    """Create timeline analysis tab"""
    timestamps = data['detailed_results'].get('timestamps', [])
    packet_sizes = data['detailed_results'].get('packet_sizes', [])
    
    if not timestamps or not packet_sizes:
        return dbc.Alert("No timeline data available", color="info")
    
    # Convert to DataFrame
    df = pd.DataFrame({
        'timestamp': pd.to_datetime(timestamps, unit='s'),
        'packet_size': packet_sizes
    })
    
    # Resample to get traffic over time
    df_resampled = df.set_index('timestamp').resample('1T').agg({
        'packet_size': ['count', 'sum', 'mean']
    }).reset_index()
    df_resampled.columns = ['timestamp', 'packet_count', 'total_bytes', 'avg_size']
    
    # Traffic timeline
    timeline_fig = go.Figure()
    timeline_fig.add_trace(go.Scatter(
        x=df_resampled['timestamp'],
        y=df_resampled['packet_count'],
        mode='lines',
        name='Packets per Minute',
        line=dict(color='blue')
    ))
    
    timeline_fig.update_layout(
        title="Network Traffic Timeline",
        xaxis_title="Time",
        yaxis_title="Packets per Minute"
    )
    
    # Packet size distribution
    size_fig = px.histogram(
        df,
        x='packet_size',
        title="Packet Size Distribution",
        nbins=50
    )
    
    return dbc.Row([
        dbc.Col([
            dcc.Graph(figure=timeline_fig)
        ], width=12),
        dbc.Col([
            dcc.Graph(figure=size_fig)
        ], width=12)
    ])


# Flask routes for API endpoints
@server.route('/api/analyze', methods=['POST'])
def api_analyze():
    """API endpoint for programmatic analysis"""
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    if file and file.filename.endswith('.pcap'):
        # Save file temporarily
        filename = secure_filename(file.filename)
        filepath = os.path.join(server.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        
        try:
            # Analyze
            analyzer = NetworkTrafficAnalyzer()
            if analyzer.load_pcap(filepath):
                results = analyzer.run_full_analysis()
                return jsonify(results)
            else:
                return jsonify({'error': 'Failed to analyze PCAP file'}), 500
        
        except Exception as e:
            return jsonify({'error': str(e)}), 500
        
        finally:
            # Clean up
            if os.path.exists(filepath):
                os.remove(filepath)
    
    return jsonify({'error': 'Invalid file format'}), 400


@server.route('/api/download_report/<format>')
def download_report(format):
    """Download analysis report in specified format"""
    global current_analyzer
    
    if current_analyzer is None:
        return jsonify({'error': 'No analysis available'}), 400
    
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=f'.{format}') as tmp:
            if format == 'csv':
                current_analyzer.export_csv_report(tmp.name)
                return send_file(tmp.name, as_attachment=True, 
                               download_name=f'traffic_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv')
            elif format == 'json':
                current_analyzer.export_json_report(tmp.name)
                return send_file(tmp.name, as_attachment=True,
                               download_name=f'traffic_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json')
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    
    return jsonify({'error': 'Invalid format'}), 400


if __name__ == '__main__':
    import base64
    print("🚀 Starting NetTrafficAnalyzer Web Interface...")
    print("📊 Access the dashboard at: http://localhost:8050")
    print("🔧 API endpoint available at: http://localhost:8050/api/analyze")
    
    app.run_server(debug=True, host='0.0.0.0', port=8050)